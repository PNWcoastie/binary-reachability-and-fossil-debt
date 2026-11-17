#![forbid(unsafe_code)]
//! Safe Rust reconstruction of `libBlurDetection.camera.samsung.so`
//! (SHA-256: `07baf5e21a19cd1c53ab61aa47c19949da47e1bbbeb66f855a67e2b2c19d5615`).
//!
//! This crate implements all five recovered AArch64 DSP routines in 100% safe
//! Rust (`#![forbid(unsafe_code)]`), replacing raw pointer arithmetic, unchecked
//! `malloc(0x4bf00)` heap buffers (`SAM-BUG-10`), and OpenCV C++ `cv::Mat` allocations
//! with bounds-checked slice operations while preserving bit-exact C ABI and IEEE-754
//! arithmetic semantics. It also provides both the binary-exact oracle reproduction and
//! the remediated fix for **`SAM-BUG-10b`** (the dead 3rd output counter in `get_cnt_lt`
//! that rendered `calc_low_texture` and the `-100` low-texture sentinel unreachable).

/// Default canonical target width (`288` pixels) used by `compute_blur` (`0x57c8`).
pub const CANONICAL_WIDTH: usize = 288;
/// Default canonical target height (`216` pixels) used by `compute_blur` (`0x57c8`).
pub const CANONICAL_HEIGHT: usize = 216;
/// Low-texture sentinel (`-100`) when `calc_low_texture` reports a flat frame.
pub const LOW_TEXTURE_SENTINEL: i32 = -100;

/// Computes first-order horizontal and vertical absolute neighbor differences (`dx`, `dy`)
/// across an active interior ROI (`width_lt × height_lt`) and applies a 2-pixel directional
/// maximum filter (`max(d[i], d[i+1])`), matching `_Z10get_dif_ltPhiiiS_` (`0x0fc8`).
///
/// # Eliminated Hazards
/// - Replaces raw pointer strides (`src + y * stride + x`) and unchecked writes into a single
///   aliased `diff_buf` pointer with bounds-checked slice indexing on disjoint `dx_buf` and `dy_buf`.
#[inline(always)]
pub fn get_dif_lt(
    src: &[u8], stride: usize, width_lt: usize, height_lt: usize, dx_buf: &mut [u8], dy_buf: &mut [u8],
) -> i32 {
    if height_lt < 1 || width_lt < 1 {
        return 0;
    }

    // Pass 1: 1st-order absolute horizontal and vertical neighbor differences.
    for y in 0..height_lt {
        let row_src = y.saturating_mul(stride);
        let next_row_src = (y + 1).saturating_mul(stride);
        let row_dst = y.saturating_mul(width_lt);
        for x in 0..width_lt.saturating_sub(1) {
            let p00 = i32::from(src.get(row_src + x).copied().unwrap_or(0));
            let p01 = i32::from(src.get(row_src + x + 1).copied().unwrap_or(0));
            let p10 = i32::from(src.get(next_row_src + x).copied().unwrap_or(0));
            if let Some(slot) = dx_buf.get_mut(row_dst + x) {
                *slot = (p00 - p01).unsigned_abs() as u8;
            }
            if let Some(slot) = dy_buf.get_mut(row_dst + x) {
                *slot = (p00 - p10).unsigned_abs() as u8;
            }
        }
    }

    // Pass 2: 2-tap directional maximum filter along X (for dx_buf) and Y (for dy_buf).
    if height_lt >= 2 && width_lt >= 2 {
        for y in 0..(height_lt - 1) {
            let row_dst = y.saturating_mul(width_lt);
            let next_row_dst = (y + 1).saturating_mul(width_lt);
            for x in 0..(width_lt - 1) {
                let x0 = dx_buf.get(row_dst + x).copied().unwrap_or(0);
                let x1 = dx_buf.get(row_dst + x + 1).copied().unwrap_or(0);
                if let Some(slot) = dx_buf.get_mut(row_dst + x) {
                    *slot = x0.max(x1);
                }
                let y0 = dy_buf.get(row_dst + x).copied().unwrap_or(0);
                let y1 = dy_buf.get(next_row_dst + x).copied().unwrap_or(0);
                if let Some(slot) = dy_buf.get_mut(row_dst + x) {
                    *slot = y0.max(y1);
                }
            }
        }
    }

    0
}

/// Partitions the filtered gradient planes (`dx_buf`, `dy_buf`) into non-overlapping
/// `4×4` blocks (`blocks_x × blocks_y`) and counts how many blocks have a 16-pixel
/// directional gradient sum strictly less than `40`, matching `_Z10get_cnt_ltPhS_iiiPiS0_S0_S0_` (`0x138c`).
///
/// # Eliminated Hazards
/// - Replaces raw out-pointer mutations (`int* out_cnt_x, int* out_cnt_y`) and two unused
///   dangling pointer arguments (`int* unused_3, int* unused_4`) with a pure `(i32, i32)` tuple.
#[inline(always)]
pub fn get_cnt_lt(
    dx_buf: &[u8], dy_buf: &[u8], stride_lt: usize, blocks_x: usize, blocks_y: usize,
) -> (i32, i32) {
    let (mut cnt_x, mut cnt_y) = (0_i32, 0_i32);
    for by in 0..blocks_y {
        for bx in 0..blocks_x {
            let (mut sx, mut sy) = (0_i32, 0_i32);
            for r in 0..4 {
                let row_off = (4 * by + r).saturating_mul(stride_lt) + 4 * bx;
                for c in 0..4 {
                    sx += i32::from(dx_buf.get(row_off + c).copied().unwrap_or(0));
                    sy += i32::from(dy_buf.get(row_off + c).copied().unwrap_or(0));
                }
            }
            if (((sx as u32) << 16) as i32) < (40 << 16) {
                cnt_x = cnt_x.wrapping_add(1);
            }
            if (((sy as u32) << 16) as i32) < (40 << 16) {
                cnt_y = cnt_y.wrapping_add(1);
            }
        }
    }
    (cnt_x, cnt_y)
}

/// Binary-exact reproduction of `_Z16calc_low_texturePhiiS_` (`0x15d4`), preserving
/// **`SAM-BUG-10b`** for differential C-oracle parity.
///
/// # `SAM-BUG-10b` (Fossilized 3rd Counter & Dead Low-Texture Sentinel)
/// In `libBlurDetection.camera.samsung.so`, `_Z16calc_low_texturePhiiS_` (`0x15d4`) zeroes four
/// 32-bit stack counters at `[sp, #0x0..0x10]` and passes their addresses as `x5`, `x6`, `x7`,
/// and `[sp]` to `_Z10get_cnt_ltPhS_iiiPiS0_S0_S0_` (`0x138c`). However, `get_cnt_lt` only writes
/// `cnt_x` (`*x5`) and `cnt_y` (`*x6`), leaving the 3rd counter at `[sp, #0x8]` (`*x7`) permanently `0`.
/// At `0x16bc..0x16d8`, `calc_low_texture` checks whether `10 * cnt_3 > 9 * total_blocks`, which
/// simplifies to `0 > thresh`, i.e. `((thresh as u32) >> 31) as i32` (`0` for all valid dimensions).
/// Use [`calc_low_texture_remediated`] to restore the intended low-texture detection.
#[inline(always)]
pub fn calc_low_texture(img: &[u8], width: usize, height: usize, work_buf: &mut [u8]) -> i32 {
    if width < 10 || height < 10 || width > 16_384 || height > 16_384 {
        return 0;
    }
    let (w9, h9) = ((width as i32) - 9, (height as i32) - 9);
    let width_lt = ((w9 - (w9 % 4)) + 2) as usize;
    let height_lt = ((h9 - (h9 % 4)) + 2) as usize;
    let plane_len = width_lt.saturating_mul(height_lt);
    let roi_offset = 4usize.saturating_mul(width).saturating_add(4);
    if img.len() < roi_offset || work_buf.len() < plane_len.saturating_mul(2) {
        return 0;
    }

    let (dx_buf, rest) = work_buf.split_at_mut(plane_len);
    let dy_buf = &mut rest[..plane_len];
    get_dif_lt(&img[roi_offset..], width, width_lt, height_lt, dx_buf, dy_buf);

    let (blocks_x, blocks_y) = (width_lt / 4, height_lt / 4);
    let (cnt_x, cnt_y) = get_cnt_lt(dx_buf, dy_buf, width_lt, blocks_x, blocks_y);
    let total_blocks = (blocks_x as i32).wrapping_mul(blocks_y as i32);
    let thresh = 9_i32.wrapping_mul(total_blocks);
    if 10_i32.wrapping_mul(cnt_x) <= thresh || 10_i32.wrapping_mul(cnt_y) <= thresh {
        return 0;
    }

    // SAM-BUG-10b: In the AArch64 binary at 0x16bc..0x16d8, get_cnt_lt leaves the 3rd stack
    // counter [sp, #0x8] at 0, so `10 * 0 > thresh` reduces to extracting the sign bit of `thresh`.
    ((thresh as u32) >> 31) as i32
}

/// Remediated version of [`calc_low_texture`] that fixes **`SAM-BUG-10b`** by removing the dead
/// 3rd-pointer check (`[sp, #0x8]`) and returning `1` whenever both horizontal and vertical
/// low-texture block counts exceed `90%` of `total_blocks` (`10 * cnt_x > 9 * total_blocks`
/// and `10 * cnt_y > 9 * total_blocks`).
#[inline(always)]
pub fn calc_low_texture_remediated(
    img: &[u8], width: usize, height: usize, work_buf: &mut [u8],
) -> i32 {
    if width < 10 || height < 10 || width > 16_384 || height > 16_384 {
        return 0;
    }
    let (w9, h9) = ((width as i32) - 9, (height as i32) - 9);
    let width_lt = ((w9 - (w9 % 4)) + 2) as usize;
    let height_lt = ((h9 - (h9 % 4)) + 2) as usize;
    let plane_len = width_lt.saturating_mul(height_lt);
    let roi_offset = 4usize.saturating_mul(width).saturating_add(4);
    if img.len() < roi_offset || work_buf.len() < plane_len.saturating_mul(2) {
        return 0;
    }

    let (dx_buf, rest) = work_buf.split_at_mut(plane_len);
    let dy_buf = &mut rest[..plane_len];
    get_dif_lt(&img[roi_offset..], width, width_lt, height_lt, dx_buf, dy_buf);

    let (blocks_x, blocks_y) = (width_lt / 4, height_lt / 4);
    let (cnt_x, cnt_y) = get_cnt_lt(dx_buf, dy_buf, width_lt, blocks_x, blocks_y);
    let total_blocks = (blocks_x as i32).wrapping_mul(blocks_y as i32);
    let thresh = 9_i32.wrapping_mul(total_blocks);
    i32::from(10_i32.wrapping_mul(cnt_x) > thresh && 10_i32.wrapping_mul(cnt_y) > thresh)
}

/// Computes the per-pixel vertical and horizontal multi-scale gradient residual packed as
/// `(res_v << 16) | res_h`, matching the inner loop of `get_blur_val` (`0x1814..0x18b0`).
#[inline(always)]
pub fn blur_multi_scale_residual(
    p00: u8, p10: u8, p01: u8, ph_p5: u8, ph_m4: u8, pv_p5: u8, pv_m4: u8,
) -> i32 {
    let dv1 = (i32::from(p00) - i32::from(p10)).abs();
    let dh1 = (i32::from(p00) - i32::from(p01)).abs();
    let dv9 = (i32::from(pv_p5) - i32::from(pv_m4)).abs();
    let dh9 = (i32::from(ph_p5) - i32::from(ph_m4)).abs();

    let res_v = (9 * (dv1 & 0xff) - dv9).max(0);
    let res_h = (9 * (dh1 & 0xff) - dh9).max(0);
    (res_v << 16) | (res_h & 0xffff)
}

/// Computes the multi-scale sharpness score in `[0, 100]` (or `-100` if `calc_low_texture`
/// is non-zero) across `16×8` macroblocks strided by 16 pixels starting at `(5, 5)`,
/// matching `get_blur_val` (`0x1710`).
///
/// # Eliminated Hazards
/// - Bounds `width` and `height` to `[10, 16_384]`, preventing negative `i32` casts and
///   32-bit `w * h` integer overflow (`SAM-BUG-10`).
/// - Replaces unchecked raw `uint16_t*` aliasing of an external `uint8_t* work_buf` with safe,
///   properly typed `Vec<u16>` residual planes and explicit zero-divisor guards.
#[inline(always)]
pub fn get_blur_val(img: &[u8], width: usize, height: usize) -> i32 {
    if width < 10 || height < 10 || width > 16_384 || height > 16_384 {
        return 0;
    }
    let total_pixels = width.saturating_mul(height);
    if img.len() < total_pixels {
        return 0;
    }

    let (w9, h9) = ((width as i32) - 9, (height as i32) - 9);
    let width_lt = ((w9 - (w9 % 4)) + 2) as usize;
    let height_lt = ((h9 - (h9 % 4)) + 2) as usize;
    let plane_len = width_lt.saturating_mul(height_lt);
    let mut work_buf = vec![0u8; plane_len.saturating_mul(2)];
    if (calc_low_texture(img, width, height, &mut work_buf) & 0xff) != 0 {
        return LOW_TEXTURE_SENTINEL;
    }

    let stride_res = width - 9;
    let res_len = (height - 9).saturating_mul(stride_res);
    let mut buf_v = vec![0u16; res_len];
    let mut buf_h = vec![0u16; res_len];

    for y in 4..(height - 5) {
        let r_off = (y - 4) * stride_res;
        for x in 4..(width - 5) {
            let packed = blur_multi_scale_residual(
                img[y * width + x], img[(y + 1) * width + x], img[y * width + x + 1],
                img[y * width + x + 5], img[y * width + x - 4], img[(y + 5) * width + x], img[(y - 4) * width + x],
            );
            buf_v[r_off + (x - 4)] = ((packed >> 16) & 0xffff) as u16;
            buf_h[r_off + (x - 4)] = (packed & 0xffff) as u16;
        }
    }

    if height < 26 || width < 26 {
        return 0;
    }

    let (mut acc_v, mut acc_h, mut ratio_v, mut ratio_h) = (0.0_f64, 0.0_f64, 0.0_f64, 0.0_f64);
    let (mut valid_v, mut valid_h) = (0_i32, 0_i32);

    let mut by = 5usize;
    while by < height - 20 {
        let mut bx = 5usize;
        while bx < width - 20 {
            let (mut sum_v1, mut sum_h1, mut sum_res_v, mut sum_res_h) = (0_i32, 0_i32, 0_i32, 0_i32);
            for r in (0..16).rev() {
                let y = by + r;
                let res_row = (y - 4) * stride_res;
                for c in 0..8 {
                    let x = bx + c;
                    let p00 = i32::from(img[y * width + x]);
                    let p10 = i32::from(img[(y + 1) * width + x]);
                    let p01 = i32::from(img[y * width + x + 1]);
                    sum_v1 += (p00 - p10).abs();
                    sum_h1 += (p00 - p01).abs();
                    sum_res_v += i32::from(buf_v[res_row + (x - 4)]);
                    sum_res_h += i32::from(buf_h[res_row + (x - 4)]);
                }
            }

            if sum_v1 != 0 { ratio_v = 1.0 - (sum_res_v as f64) / ((9 * sum_v1) as f64); }
            if sum_h1 != 0 { ratio_h = 1.0 - (sum_res_h as f64) / ((9 * sum_h1) as f64); }
            if (((sum_v1.wrapping_sub(400)) as u32) >> 4) < 475 { acc_v += ratio_v; valid_v += 1; }
            if (((sum_h1.wrapping_sub(400)) as u32) >> 4) < 475 { acc_h += ratio_h; valid_h += 1; }
            bx += 16;
        }
        by += 16;
    }

    let final_ratio = if acc_v > acc_h && valid_v > 0 {
        acc_v / (valid_v as f64)
    } else if acc_h != 0.0 && valid_h > 0 {
        acc_h / (valid_h as f64)
    } else {
        0.0
    };
    (final_ratio * 100.0) as i32
}

/// Remediated version of [`get_blur_val`] that uses [`calc_low_texture_remediated`] (`SAM-BUG-10b` fix)
/// so flat/low-texture images return [`LOW_TEXTURE_SENTINEL`] (`-100`).
#[inline(always)]
pub fn get_blur_val_remediated(img: &[u8], width: usize, height: usize) -> i32 {
    if width < 10 || height < 10 || width > 16_384 || height > 16_384 {
        return 0;
    }
    let total_pixels = width.saturating_mul(height);
    if img.len() < total_pixels {
        return 0;
    }
    let (w9, h9) = ((width as i32) - 9, (height as i32) - 9);
    let width_lt = ((w9 - (w9 % 4)) + 2) as usize;
    let height_lt = ((h9 - (h9 % 4)) + 2) as usize;
    let plane_len = width_lt.saturating_mul(height_lt);
    let mut work_buf = vec![0u8; plane_len.saturating_mul(2)];
    if (calc_low_texture_remediated(img, width, height, &mut work_buf) & 0xff) != 0 {
        return LOW_TEXTURE_SENTINEL;
    }
    get_blur_val(img, width, height)
}

/// Top-level entry point matching `compute_blur` (`0x1c08`): resizes an input grayscale frame
/// to `288×216` using bilinear interpolation (`INTER_LINEAR`) when its dimensions differ from
/// `288×216`, invokes `get_blur_val`, and returns `100 - get_blur_val(...)`.
///
/// # Eliminated Hazards
/// - Replaces unchecked `malloc(0x4bf00)` (`NULL`-dereference hazard `SAM-BUG-10`) and C++ `cv::Mat`
///   lifecycle management with safe Rust `Vec<u8>` allocation.
pub fn compute_blur(img: &[u8], width: usize, height: usize) -> i32 {
    if width == 0 || height == 0 || width > 16_384 || height > 16_384 || img.len() < width.saturating_mul(height) {
        return 100;
    }
    if width == CANONICAL_WIDTH && height == CANONICAL_HEIGHT {
        return 100 - get_blur_val(img, CANONICAL_WIDTH, CANONICAL_HEIGHT);
    }

    let mut resized = vec![0u8; CANONICAL_WIDTH * CANONICAL_HEIGHT];
    let scale_x = (width as f64) / (CANONICAL_WIDTH as f64);
    let scale_y = (height as f64) / (CANONICAL_HEIGHT as f64);

    for dy in 0..CANONICAL_HEIGHT {
        let fy = ((dy as f64) + 0.5) * scale_y - 0.5;
        let sy = fy.floor() as isize;
        let wy = (fy - (sy as f64)).clamp(0.0, 1.0);
        let y0 = sy.clamp(0, (height as isize) - 1) as usize;
        let y1 = (sy + 1).clamp(0, (height as isize) - 1) as usize;

        for dx in 0..CANONICAL_WIDTH {
            let fx = ((dx as f64) + 0.5) * scale_x - 0.5;
            let sx = fx.floor() as isize;
            let wx = (fx - (sx as f64)).clamp(0.0, 1.0);
            let x0 = sx.clamp(0, (width as isize) - 1) as usize;
            let x1 = (sx + 1).clamp(0, (width as isize) - 1) as usize;

            let p00 = f64::from(img[y0 * width + x0]);
            let p01 = f64::from(img[y0 * width + x1]);
            let p10 = f64::from(img[y1 * width + x0]);
            let p11 = f64::from(img[y1 * width + x1]);

            let top = p00 + wx * (p01 - p00);
            let bot = p10 + wx * (p11 - p10);
            resized[dy * CANONICAL_WIDTH + dx] = (top + wy * (bot - top) + 0.5).clamp(0.0, 255.0) as u8;
        }
    }

    100 - get_blur_val(&resized, CANONICAL_WIDTH, CANONICAL_HEIGHT)
}

/// Deterministic single-slice wrapper for FFI parity verification of `get_dif_lt` + `get_cnt_lt`.
/// Maps `data` into a `20×20` tile (`width_lt = 10, height_lt = 10, blocks_x = 2, blocks_y = 2`)
/// and returns `(cnt_x << 16) | cnt_y`.
#[inline(always)]
pub fn blur_dif_lt_kernel(data: &[u8]) -> i32 {
    let mut tile = [0u8; 400];
    if !data.is_empty() {
        for (i, slot) in tile.iter_mut().enumerate() {
            *slot = data[(i.wrapping_mul(13).wrapping_add(i / 20)) % data.len()];
        }
    }
    let (mut dx_buf, mut dy_buf) = ([0u8; 100], [0u8; 100]);
    get_dif_lt(&tile[84..], 20, 10, 10, &mut dx_buf, &mut dy_buf);
    let (cnt_x, cnt_y) = get_cnt_lt(&dx_buf, &dy_buf, 10, 2, 2);
    (cnt_x << 16) | (cnt_y & 0xffff)
}

/// Deterministic single-slice wrapper for FFI parity verification of the complete `get_blur_val`
/// pipeline on a `32×32` tile derived from `data`.
#[inline(always)]
pub fn get_blur_val_tile(data: &[u8]) -> i32 {
    let mut tile = [0u8; 32 * 32];
    if !data.is_empty() {
        for (i, slot) in tile.iter_mut().enumerate() {
            *slot = data[(i.wrapping_mul(13).wrapping_add(i >> 5)) % data.len()];
        }
    }
    get_blur_val(&tile, 32, 32)
}
