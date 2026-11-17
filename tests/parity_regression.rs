#![forbid(unsafe_code)]
//! Standalone regression test suite verifying recorded C oracle test vectors
//! (`0 ULP` bit-exact equivalence), all `30,118` deterministic SplitMix64
//! (`seed = 1337420`) + boundary FFI parity vectors against standalone AArch64
//! instruction-level reference oracles with pinned 64-bit FNV-1a output digests,
//! and `SAM-BUG-10` / `SAM-BUG-10b` remediation proofs against `s9_blur_detection`.

use s9_blur_detection::{
    blur_dif_lt_kernel, blur_multi_scale_residual, calc_low_texture,
    calc_low_texture_remediated, compute_blur, get_blur_val, get_blur_val_remediated,
    get_blur_val_tile, get_cnt_lt, get_dif_lt, CANONICAL_HEIGHT, CANONICAL_WIDTH,
    LOW_TEXTURE_SENTINEL,
};

struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    #[inline(always)]
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }

    #[inline(always)]
    fn next_u8(&mut self) -> u8 {
        (self.next_u64() & 0xff) as u8
    }
}

struct Fnv1a64 {
    hash: u64,
}

impl Fnv1a64 {
    const OFFSET_BASIS: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;

    const fn new() -> Self {
        Self { hash: Self::OFFSET_BASIS }
    }

    #[inline(always)]
    fn write_i32(&mut self, val: i32) {
        for b in val.to_le_bytes() {
            self.hash ^= u64::from(b);
            self.hash = self.hash.wrapping_mul(Self::PRIME);
        }
    }

    const fn finish(&self) -> u64 {
        self.hash
    }
}

#[inline(always)]
fn c_oracle_blur_multi_scale_residual(
    p00: u8, p10: u8, p01: u8, ph_p5: u8, ph_m4: u8, pv_p5: u8, pv_m4: u8,
) -> i32 {
    // AArch64 get_blur_val inner loop (0x1814..0x18b0)
    let dv1 = { let d = i32::from(p00) - i32::from(p10); if d < 0 { -d } else { d } };
    let dh1 = { let d = i32::from(p00) - i32::from(p01); if d < 0 { -d } else { d } };
    let dv9 = { let d = i32::from(pv_p5) - i32::from(pv_m4); if d < 0 { -d } else { d } };
    let dh9 = { let d = i32::from(ph_p5) - i32::from(ph_m4); if d < 0 { -d } else { d } };
    let res_v = { let r = 9 * (dv1 & 0xff) - dv9; if r < 0 { 0 } else { r } };
    let res_h = { let r = 9 * (dh1 & 0xff) - dh9; if r < 0 { 0 } else { r } };
    (res_v << 16) | (res_h & 0xffff)
}

#[inline(always)]
fn c_oracle_dif_and_cnt(
    src: &[u8], stride: usize, w_lt: usize, h_lt: usize, dx_buf: &mut [u8], dy_buf: &mut [u8],
) -> (i32, i32) {
    // AArch64 _Z10get_dif_ltPhiiiS_ (0x0fc8) + _Z10get_cnt_ltPhS_iiiPiS0_S0_S0_ (0x138c)
    for y in 0..h_lt {
        for x in 0..(w_lt - 1) {
            let p00 = i32::from(src[y * stride + x]);
            let p01 = i32::from(src[y * stride + x + 1]);
            let p10 = i32::from(src[(y + 1) * stride + x]);
            let (dx, dy) = (p00 - p01, p00 - p10);
            dx_buf[y * w_lt + x] = (if dx < 0 { -dx } else { dx }) as u8;
            dy_buf[y * w_lt + x] = (if dy < 0 { -dy } else { dy }) as u8;
        }
    }
    for y in 0..(h_lt - 1) {
        for x in 0..(w_lt - 1) {
            let (x0, x1) = (dx_buf[y * w_lt + x], dx_buf[y * w_lt + x + 1]);
            dx_buf[y * w_lt + x] = if x0 > x1 { x0 } else { x1 };
            let (y0, y1) = (dy_buf[y * w_lt + x], dy_buf[(y + 1) * w_lt + x]);
            dy_buf[y * w_lt + x] = if y0 > y1 { y0 } else { y1 };
        }
    }
    let (blocks_x, blocks_y) = (w_lt / 4, h_lt / 4);
    let (mut cnt_x, mut cnt_y) = (0_i32, 0_i32);
    for by in 0..blocks_y {
        for bx in 0..blocks_x {
            let (mut sx, mut sy) = (0_i32, 0_i32);
            for r in 0..4 {
                let off = (4 * by + r) * w_lt + 4 * bx;
                sx += i32::from(dx_buf[off]) + i32::from(dx_buf[off + 1]) + i32::from(dx_buf[off + 2]) + i32::from(dx_buf[off + 3]);
                sy += i32::from(dy_buf[off]) + i32::from(dy_buf[off + 1]) + i32::from(dy_buf[off + 2]) + i32::from(dy_buf[off + 3]);
            }
            if (((sx as u32) << 16) as i32) < (40 << 16) { cnt_x += 1; }
            if (((sy as u32) << 16) as i32) < (40 << 16) { cnt_y += 1; }
        }
    }
    (cnt_x, cnt_y)
}

#[inline(always)]
fn c_oracle_blur_dif_lt_kernel(data: &[u8]) -> i32 {
    let mut tile = [0_u8; 400];
    if !data.is_empty() {
        for (i, slot) in tile.iter_mut().enumerate() {
            *slot = data[(i.wrapping_mul(13).wrapping_add(i / 20)) % data.len()];
        }
    }
    let (mut dx_buf, mut dy_buf) = ([0_u8; 100], [0_u8; 100]);
    let (cnt_x, cnt_y) = c_oracle_dif_and_cnt(&tile[84..], 20, 10, 10, &mut dx_buf, &mut dy_buf);
    (cnt_x << 16) | (cnt_y & 0xffff)
}

#[inline(always)]
fn c_oracle_get_blur_val_tile(data: &[u8]) -> i32 {
    // AArch64 get_blur_val (0x1710) on 32x32 tile (stride_res = 23, w_lt = 22, h_lt = 22)
    let mut img = [0_u8; 1024];
    if !data.is_empty() {
        for (i, slot) in img.iter_mut().enumerate() {
            *slot = data[(i.wrapping_mul(13).wrapping_add(i >> 5)) % data.len()];
        }
    }
    let (mut dx_buf, mut dy_buf) = ([0_u8; 484], [0_u8; 484]);
    let (cnt_x, cnt_y) = c_oracle_dif_and_cnt(&img[4 * 32 + 4..], 32, 22, 22, &mut dx_buf, &mut dy_buf);
    let thresh = 9 * 25;
    let lt_ret = if 10 * cnt_x <= thresh || 10 * cnt_y <= thresh {
        0
    } else {
        ((thresh as u32) >> 31) as i32
    };
    if (lt_ret & 0xff) != 0 {
        return -100;
    }

    let stride_res = 23_usize;
    let (mut buf_v, mut buf_h) = ([0_u16; 529], [0_u16; 529]);
    for y in 4..27_usize {
        for x in 4..27_usize {
            let packed = c_oracle_blur_multi_scale_residual(
                img[y * 32 + x], img[(y + 1) * 32 + x], img[y * 32 + x + 1],
                img[y * 32 + x + 5], img[y * 32 + x - 4], img[(y + 5) * 32 + x], img[(y - 4) * 32 + x],
            );
            buf_v[(y - 4) * stride_res + (x - 4)] = ((packed >> 16) & 0xffff) as u16;
            buf_h[(y - 4) * stride_res + (x - 4)] = (packed & 0xffff) as u16;
        }
    }

    let (mut acc_v, mut acc_h, mut ratio_v, mut ratio_h) = (0.0_f64, 0.0_f64, 0.0_f64, 0.0_f64);
    let (mut valid_v, mut valid_h) = (0_i32, 0_i32);
    let (by, bx) = (5_usize, 5_usize);
    let (mut sum_v1, mut sum_h1, mut sum_res_v, mut sum_res_h) = (0_i32, 0_i32, 0_i32, 0_i32);
    for r in (0..16_usize).rev() {
        let y = by + r;
        for c in 0..8_usize {
            let x = bx + c;
            let p00 = i32::from(img[y * 32 + x]);
            let p10 = i32::from(img[(y + 1) * 32 + x]);
            let p01 = i32::from(img[y * 32 + x + 1]);
            sum_v1 += (p00 - p10).abs();
            sum_h1 += (p00 - p01).abs();
            sum_res_v += i32::from(buf_v[(y - 4) * stride_res + (x - 4)]);
            sum_res_h += i32::from(buf_h[(y - 4) * stride_res + (x - 4)]);
        }
    }
    if sum_v1 != 0 { ratio_v = 1.0 - (sum_res_v as f64) / ((9 * sum_v1) as f64); }
    if sum_h1 != 0 { ratio_h = 1.0 - (sum_res_h as f64) / ((9 * sum_h1) as f64); }
    if (((sum_v1.wrapping_sub(400)) as u32) >> 4) < 475 { acc_v += ratio_v; valid_v += 1; }
    if (((sum_h1.wrapping_sub(400)) as u32) >> 4) < 475 { acc_h += ratio_h; valid_h += 1; }
    let final_ratio = if acc_v > acc_h && valid_v > 0 {
        acc_v / (valid_v as f64)
    } else if acc_h != 0.0 && valid_h > 0 {
        acc_h / (valid_h as f64)
    } else {
        0.0
    };
    (final_ratio * 100.0) as i32
}

#[test]
fn verified_c_oracle_regression_vectors() {
    let cases: &[(&[u8], i32, i32)] = &[
        (&[], 0, 0x0004_0004),
        (&[0x00], 0, 0x0004_0004),
        (&[0xff], 0, 0x0004_0004),
        (b"ARGON_ZEROG_PARITY_V1", 13, 0x0000_0000),
        (
            &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
            15,
            0x0000_0000,
        ),
        (&[0xa5; 64], 0, 0x0004_0004),
    ];
    for (idx, &(input, expected_tile, expected_dif)) in cases.iter().enumerate() {
        assert_eq!(get_blur_val_tile(input), expected_tile, "Tile vector #{} mismatch", idx + 1);
        assert_eq!(blur_dif_lt_kernel(input), expected_dif, "Dif vector #{} mismatch", idx + 1);
    }
}

#[test]
fn sam_bug_10_and_10b_remediation_proofs() {
    // 1. SAM-BUG-10: Oversized / undersized dimensions and short buffers safely return 0 / 100.
    let (mut small_work, mut small_dy) = ([0_u8; 64], [0_u8; 64]);
    for &(w, h) in &[(0, 0), (5, 5), (9, 216), (288, 9), (16_385, 216), (100_000, 100_000)] {
        assert_eq!(calc_low_texture(&[], w, h, &mut small_work), 0);
        assert_eq!(calc_low_texture_remediated(&[], w, h, &mut small_work), 0);
        assert_eq!(get_blur_val(&[], w, h), 0);
        assert_eq!(get_blur_val_remediated(&[], w, h), 0);
        assert_eq!(compute_blur(&[], w, h), 100);
    }
    assert_eq!(get_dif_lt(&[], 20, 0, 10, &mut small_work, &mut small_dy), 0);

    // 2. SAM-BUG-10b: On a flat uniform 288x216 frame, get_cnt_lt counts all blocks as low-texture,
    //    yet binary-exact calc_low_texture returns 0 because get_cnt_lt never writes the 3rd output
    //    pointer [sp, #0x8]. Remediated functions restore the intended low-texture detection.
    let flat_frame = vec![128_u8; CANONICAL_WIDTH * CANONICAL_HEIGHT];
    let mut work_buf = vec![0_u8; CANONICAL_WIDTH * CANONICAL_HEIGHT * 2];
    assert_eq!(calc_low_texture(&flat_frame, CANONICAL_WIDTH, CANONICAL_HEIGHT, &mut work_buf), 0);
    assert_eq!(calc_low_texture_remediated(&flat_frame, CANONICAL_WIDTH, CANONICAL_HEIGHT, &mut work_buf), 1);
    assert_eq!(get_blur_val(&flat_frame, CANONICAL_WIDTH, CANONICAL_HEIGHT), 0);
    assert_eq!(get_blur_val_remediated(&flat_frame, CANONICAL_WIDTH, CANONICAL_HEIGHT), LOW_TEXTURE_SENTINEL);
    assert_eq!(compute_blur(&flat_frame, CANONICAL_WIDTH, CANONICAL_HEIGHT), 100);

    let (cx, cy) = get_cnt_lt(&[0_u8; 100], &[0_u8; 100], 10, 2, 2);
    assert_eq!((cx, cy), (4, 4));
}

#[test]
fn splitmix64_30118_ffi_parity_vectors_and_fnv1a_digests() {
    const SEED: u64 = 1337420;
    const U8_EDGES: [u8; 8] = [0x00, 0x01, 0x27, 0x28, 0x7f, 0x80, 0xfe, 0xff];

    // 1. blur_multi_scale_residual: 64 boundary vectors + 10,000 SplitMix64 vectors = 10,064
    let mut ms_rng = SplitMix64::new(SEED);
    let mut ms_hash = Fnv1a64::new();
    let mut ms_count = 0_usize;
    for i in 0..64_usize {
        let a = [
            U8_EDGES[i % 8], U8_EDGES[(i + 1) % 8], U8_EDGES[(i + 2) % 8], U8_EDGES[(i + 3) % 8],
            U8_EDGES[(i / 8) % 8], U8_EDGES[(i / 8 + 3) % 8], U8_EDGES[(i / 8 + 5) % 8],
        ];
        let actual = blur_multi_scale_residual(a[0], a[1], a[2], a[3], a[4], a[5], a[6]);
        let oracle = c_oracle_blur_multi_scale_residual(a[0], a[1], a[2], a[3], a[4], a[5], a[6]);
        assert_eq!(actual, oracle);
        ms_hash.write_i32(actual);
        ms_count += 1;
    }
    for _ in 0..10_000_usize {
        let a = [
            ms_rng.next_u8(), ms_rng.next_u8(), ms_rng.next_u8(), ms_rng.next_u8(),
            ms_rng.next_u8(), ms_rng.next_u8(), ms_rng.next_u8(),
        ];
        let actual = blur_multi_scale_residual(a[0], a[1], a[2], a[3], a[4], a[5], a[6]);
        let oracle = c_oracle_blur_multi_scale_residual(a[0], a[1], a[2], a[3], a[4], a[5], a[6]);
        assert_eq!(actual, oracle);
        ms_hash.write_i32(actual);
        ms_count += 1;
    }
    assert_eq!(ms_count, 10_064);

    // 2. blur_dif_lt_kernel & 3. get_blur_val_tile: 27 boundary + 10,000 SplitMix64 = 10,027 each
    let (mut dk_rng, mut bv_rng) = (SplitMix64::new(SEED), SplitMix64::new(SEED));
    let (mut dk_hash, mut bv_hash) = (Fnv1a64::new(), Fnv1a64::new());
    let (mut dk_count, mut bv_count) = (0_usize, 0_usize);
    let mut buf = [0_u8; 64];
    for b_idx in 0..27_usize {
        let slice: &[u8] = match b_idx {
            0 => &[],
            1 => &[0x00],
            2 => &[0xff],
            3 => b"ARGON_ZEROG_PARITY_V1",
            4 => &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
            5 => &[0xa5; 64],
            6 => &[0x80; 64],
            7 => &[0x00; 64],
            8 => &[0xff; 64],
            _ => {
                let len = b_idx - 7;
                for (k, slot) in buf.iter_mut().take(len).enumerate() {
                    *slot = if (k + b_idx) % 2 == 0 { 0x55 } else { 0xaa };
                }
                &buf[..len]
            }
        };
        let dk_actual = blur_dif_lt_kernel(slice);
        assert_eq!(dk_actual, c_oracle_blur_dif_lt_kernel(slice));
        dk_hash.write_i32(dk_actual);
        dk_count += 1;

        let bv_actual = get_blur_val_tile(slice);
        assert_eq!(bv_actual, c_oracle_get_blur_val_tile(slice));
        bv_hash.write_i32(bv_actual);
        bv_count += 1;
    }
    for _ in 0..10_000_usize {
        let len = ((dk_rng.next_u64() as usize) % 64) + 1;
        for chunk in buf[..len].chunks_mut(8) {
            let bytes = dk_rng.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        let dk_actual = blur_dif_lt_kernel(&buf[..len]);
        assert_eq!(dk_actual, c_oracle_blur_dif_lt_kernel(&buf[..len]));
        dk_hash.write_i32(dk_actual);
        dk_count += 1;

        let len_bv = ((bv_rng.next_u64() as usize) % 64) + 1;
        for chunk in buf[..len_bv].chunks_mut(8) {
            let bytes = bv_rng.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        let bv_actual = get_blur_val_tile(&buf[..len_bv]);
        assert_eq!(bv_actual, c_oracle_get_blur_val_tile(&buf[..len_bv]));
        bv_hash.write_i32(bv_actual);
        bv_count += 1;
    }
    assert_eq!(dk_count, 10_027);
    assert_eq!(bv_count, 10_027);
    assert_eq!(ms_hash.finish(), 0x14cd_4b02_1b22_c0fd);
    assert_eq!(dk_hash.finish(), 0xb637_e542_8d55_5071);
    assert_eq!(bv_hash.finish(), 0x8579_3ffe_6e04_6840);
    assert_eq!(ms_count + dk_count + bv_count, 30_118);
}
