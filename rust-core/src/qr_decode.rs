//! Offline QR decoding shared by both clients. A short list of image repairs runs
//! in order until one yields a code, so cropped, line-gapped, inverted and noisy
//! captures still read. Decoded text is inert data: callers verify it as a signed
//! invite or verification token before trusting it.

use crate::AbyssalError;
use zeroize::Zeroizing;

pub const MAX_QR_TEXT_BYTES: usize = 2048;
const MAX_SIDE: u32 = 2048;
const MAX_PIXELS: u64 = 4 * 1024 * 1024;
/// Below this side a halved image no longer holds even a version-1 code.
const MIN_HALVED_SIDE: usize = 42;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Repair {
    None,
    Close(usize),
    Halve,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Pass {
    inverted: bool,
    repair: Repair,
}

const fn pass(inverted: bool, repair: Repair) -> Pass {
    Pass { inverted, repair }
}

/// A live camera frame gets a few cheap passes because the next frame follows shortly.
const FRAME_PASSES: &[Pass] = &[
    pass(false, Repair::None),
    pass(true, Repair::None),
    pass(false, Repair::Close(1)),
];

/// A still image gets every pass because it is all there is:
///  - Close(r): fills light gaps up to 2r px, such as terminal line spacing
///  - Halve: area-averages 2x2 blocks, smoothing sensor noise and thin gaps
///  - inverted: light-on-dark codes from dark terminals and themes
const IMAGE_PASSES: &[Pass] = &[
    pass(false, Repair::None),
    pass(false, Repair::Close(1)),
    pass(false, Repair::Close(2)),
    pass(false, Repair::Close(3)),
    pass(false, Repair::Halve),
    pass(true, Repair::None),
    pass(true, Repair::Close(1)),
    pass(true, Repair::Close(2)),
    pass(true, Repair::Halve),
];

struct Raster {
    pixels: Zeroizing<Vec<u8>>,
    width: usize,
    height: usize,
}

#[uniffi::export]
pub fn decode_qr_luminance(
    luminance: Vec<u8>,
    width: u32,
    height: u32,
    thorough: bool,
) -> Result<Option<String>, AbyssalError> {
    let luminance = Zeroizing::new(luminance);
    let pixels = u64::from(width) * u64::from(height);
    if width == 0
        || height == 0
        || width > MAX_SIDE
        || height > MAX_SIDE
        || pixels > MAX_PIXELS
        || luminance.len() as u64 != pixels
    {
        return Err(AbyssalError::Failure {
            detail: "QR frame rejected".to_owned(),
        });
    }
    let source = Raster {
        pixels: luminance,
        width: width as usize,
        height: height as usize,
    };
    let passes = if thorough { IMAGE_PASSES } else { FRAME_PASSES };
    Ok(passes.iter().find_map(|pass| decode_pass(&source, *pass)))
}

fn decode_pass(source: &Raster, pass: Pass) -> Option<String> {
    let inverted;
    let base = if pass.inverted {
        inverted = Raster {
            pixels: Zeroizing::new(source.pixels.iter().map(|value| 255 - value).collect()),
            width: source.width,
            height: source.height,
        };
        &inverted
    } else {
        source
    };
    match pass.repair {
        Repair::None => read_grids(base),
        Repair::Close(radius) => read_grids(&close_light_gaps(base, radius)),
        Repair::Halve => {
            if base.width < MIN_HALVED_SIDE * 2 || base.height < MIN_HALVED_SIDE * 2 {
                return None;
            }
            read_grids(&halve(base))
        }
    }
}

fn read_grids(raster: &Raster) -> Option<String> {
    let mut prepared =
        rqrr::PreparedImage::prepare_from_greyscale(raster.width, raster.height, |x, y| {
            raster.pixels[y * raster.width + x]
        });
    prepared.detect_grids().into_iter().find_map(|grid| {
        let (_, text) = grid.decode().ok()?;
        let text = Zeroizing::new(text);
        (!text.is_empty() && text.len() <= MAX_QR_TEXT_BYTES).then(|| text.to_string())
    })
}

/// Greyscale closing of dark features: a min filter then a max filter, each square.
fn close_light_gaps(raster: &Raster, radius: usize) -> Raster {
    let darkened = square_filter(raster, radius, u8::min);
    square_filter(&darkened, radius, u8::max)
}

fn square_filter(raster: &Raster, radius: usize, pick: fn(u8, u8) -> u8) -> Raster {
    let (width, height) = (raster.width, raster.height);
    let mut horizontal = Zeroizing::new(vec![0_u8; raster.pixels.len()]);
    for y in 0..height {
        let row = &raster.pixels[y * width..(y + 1) * width];
        for x in 0..width {
            let window = &row[x.saturating_sub(radius)..=(x + radius).min(width - 1)];
            horizontal[y * width + x] = window.iter().copied().fold(row[x], pick);
        }
    }
    let mut pixels = Zeroizing::new(vec![0_u8; raster.pixels.len()]);
    for y in 0..height {
        for x in 0..width {
            pixels[y * width + x] = (y.saturating_sub(radius)..=(y + radius).min(height - 1))
                .map(|row| horizontal[row * width + x])
                .fold(horizontal[y * width + x], pick);
        }
    }
    Raster {
        pixels,
        width,
        height,
    }
}

fn halve(raster: &Raster) -> Raster {
    let (width, height) = (raster.width / 2, raster.height / 2);
    let mut pixels = Zeroizing::new(vec![0_u8; width * height]);
    for y in 0..height {
        for x in 0..width {
            let at = |dx: usize, dy: usize| {
                u16::from(raster.pixels[(y * 2 + dy) * raster.width + x * 2 + dx])
            };
            pixels[y * width + x] = ((at(0, 0) + at(1, 0) + at(0, 1) + at(1, 1)) / 4) as u8;
        }
    }
    Raster {
        pixels,
        width,
        height,
    }
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen(js_name = decodeQrLuminance)]
pub fn wasm_decode_qr_luminance(
    luminance: Vec<u8>,
    width: u32,
    height: u32,
    thorough: bool,
) -> Result<Option<String>, wasm_bindgen::JsValue> {
    decode_qr_luminance(luminance, width, height, thorough)
        .map_err(|_| wasm_bindgen::JsValue::from_str("QR frame rejected"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use qrcode::{Color, EcLevel, QrCode};

    const INVITE_BODY: &str = "Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z";

    fn invite() -> String {
        format!("abyssal:invite:{}", INVITE_BODY.repeat(10))
    }

    #[derive(Clone, Copy)]
    struct Render {
        scale: usize,
        margin: usize,
        gap_rows: usize,
        invert: bool,
        noise: i32,
        dark: i32,
        light: i32,
        crop: usize,
    }

    const PLAIN: Render = Render {
        scale: 4,
        margin: 4,
        gap_rows: 0,
        invert: false,
        noise: 0,
        dark: 0,
        light: 255,
        crop: 0,
    };

    fn render(text: &str, options: Render) -> (Vec<u8>, u32, u32) {
        let code = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::M).unwrap();
        let modules = code.width();
        let colors = code.to_colors();
        let side = (modules + 2 * options.margin) * options.scale - 2 * options.crop;
        let mut seed = 7_u64;
        let mut pixels = vec![0_u8; side * side];
        for y in 0..side {
            for x in 0..side {
                let (source_x, source_y) = (x + options.crop, y + options.crop);
                let in_gap = options.gap_rows > 0
                    && source_y % options.scale >= options.scale - options.gap_rows;
                let (module_x, module_y) = (source_x / options.scale, source_y / options.scale);
                let inside = (options.margin..modules + options.margin).contains(&module_x)
                    && (options.margin..modules + options.margin).contains(&module_y);
                let dark = !in_gap
                    && inside
                    && colors[(module_y - options.margin) * modules + module_x - options.margin]
                        == Color::Dark;
                let level = if dark != options.invert {
                    options.dark
                } else {
                    options.light
                };
                seed = seed
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                let jitter = if options.noise == 0 {
                    0
                } else {
                    ((seed >> 33) % 1000) as i32 * options.noise / 1000 - options.noise / 2
                };
                pixels[y * side + x] = (level + jitter).clamp(0, 255) as u8;
            }
        }
        (pixels, side as u32, side as u32)
    }

    fn decode(raster: (Vec<u8>, u32, u32), thorough: bool) -> Option<String> {
        decode_qr_luminance(raster.0, raster.1, raster.2, thorough).unwrap()
    }

    #[test]
    fn reads_clean_borderless_and_cropped_codes() {
        let text = invite();
        assert_eq!(decode(render(&text, PLAIN), false), Some(text.clone()));
        let borderless = Render { margin: 0, ..PLAIN };
        assert_eq!(decode(render(&text, borderless), true), Some(text.clone()));
        let cropped = Render {
            margin: 1,
            crop: 3,
            ..PLAIN
        };
        assert_eq!(decode(render(&text, cropped), true), Some(text));
    }

    #[test]
    fn reads_terminal_screenshots_with_blank_lines_between_rows() {
        let text = invite();
        for (scale, gap_rows) in [(6, 2), (8, 3), (10, 4)] {
            let gapped = Render {
                scale,
                gap_rows,
                margin: 2,
                ..PLAIN
            };
            let raster = render(&text, gapped);
            let source = Raster {
                pixels: Zeroizing::new(raster.0.clone()),
                width: raster.1 as usize,
                height: raster.2 as usize,
            };
            assert_eq!(decode_pass(&source, pass(false, Repair::None)), None);
            assert_eq!(
                decode(raster, true),
                Some(text.clone()),
                "{gap_rows}px gaps in {scale}px rows"
            );
        }
    }

    #[test]
    fn reads_light_on_dark_codes_from_stills_and_frames() {
        let text = invite();
        let inverted = Render {
            invert: true,
            ..PLAIN
        };
        assert_eq!(decode(render(&text, inverted), true), Some(text.clone()));
        assert_eq!(decode(render(&text, inverted), false), Some(text));
    }

    #[test]
    fn reads_noisy_low_contrast_photos() {
        let text = invite();
        let noisy = Render {
            noise: 60,
            dark: 70,
            light: 190,
            margin: 2,
            ..PLAIN
        };
        assert_eq!(decode(render(&text, noisy), true), Some(text));
    }

    #[test]
    fn rejects_malformed_frames_and_finds_nothing_in_blank_images() {
        for (len, width, height) in [(0, 0, 4), (4, 4, 0), (3, 2, 2), (4, 4097, 1)] {
            assert!(decode_qr_luminance(vec![255; len], width, height, true).is_err());
        }
        let too_many = MAX_PIXELS as u32 / MAX_SIDE + 1;
        assert!(decode_qr_luminance(vec![0; 4], MAX_SIDE, too_many, true).is_err());
        assert_eq!(decode((vec![255; 300 * 300], 300, 300), true), None);
        assert_eq!(decode((vec![0; 300 * 300], 300, 300), true), None);
    }

    #[test]
    fn repairs_close_thin_gaps_and_halve_by_area() {
        let raster = Raster {
            pixels: Zeroizing::new(vec![0, 255, 0, 0, 255, 0, 0, 255, 0]),
            width: 3,
            height: 3,
        };
        assert_eq!(close_light_gaps(&raster, 1).pixels[..3], [0, 0, 0]);
        let halved = halve(&Raster {
            pixels: Zeroizing::new(vec![0, 255, 255, 255]),
            width: 2,
            height: 2,
        });
        assert_eq!((halved.width, halved.height, halved.pixels[0]), (1, 1, 191));
    }
}
