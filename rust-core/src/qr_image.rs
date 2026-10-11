//! Bounded in-memory raster normalization for offline QR imports on both clients.

use crate::AbyssalError;
use image::{ColorType, ImageDecoder, ImageFormat, ImageReader, Limits};
use std::io::Cursor;
#[cfg(target_arch = "wasm32")]
use zeroize::Zeroize;
use zeroize::Zeroizing;

pub const MAX_QR_IMAGE_BYTES: usize = 8 * 1024 * 1024;
const MAX_PIXELS: u64 = 4 * 1024 * 1024;
const MAX_SIDE: u32 = 4096;
const OUTPUT_SIDE: u32 = 960;

#[derive(uniffi::Record)]
pub struct QrImage {
    pub width: u32,
    pub height: u32,
    pub luminance: Vec<u8>,
}

#[uniffi::export]
pub fn decode_qr_image(bytes: Vec<u8>, declared_mime: String) -> Result<QrImage, AbyssalError> {
    decode_inner(&Zeroizing::new(bytes), &declared_mime).map_err(|_| AbyssalError::Failure {
        detail: "QR image rejected".to_owned(),
    })
}

fn decode_inner(bytes: &[u8], declared_mime: &str) -> Result<QrImage, ()> {
    if bytes.is_empty() || bytes.len() > MAX_QR_IMAGE_BYTES {
        return Err(());
    }
    let format = image::guess_format(bytes).map_err(|_| ())?;
    let mime = match format {
        ImageFormat::Png => "image/png",
        ImageFormat::Jpeg => "image/jpeg",
        _ => return Err(()),
    };
    if !declared_mime.is_empty() && declared_mime != mime {
        return Err(());
    }
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_SIDE);
    limits.max_image_height = Some(MAX_SIDE);
    limits.max_alloc = Some(32 * 1024 * 1024);
    let mut reader = ImageReader::with_format(Cursor::new(bytes), format);
    reader.limits(limits);
    let decoder = reader.into_decoder().map_err(|_| ())?;
    let (width, height) = decoder.dimensions();
    let pixels = u64::from(width) * u64::from(height);
    if width == 0 || height == 0 || width > MAX_SIDE || height > MAX_SIDE || pixels > MAX_PIXELS {
        return Err(());
    }
    let channels = match decoder.color_type() {
        ColorType::L8 => 1,
        ColorType::La8 => 2,
        ColorType::Rgb8 => 3,
        ColorType::Rgba8 => 4,
        _ => return Err(()),
    };
    let total = pixels * channels;
    if decoder.total_bytes() != total {
        return Err(());
    }
    // Explicitly bound our output allocation independently of decoder limits.
    let mut decoded = Zeroizing::new(vec![0_u8; total as usize]);
    decoder.read_image(&mut decoded).map_err(|_| ())?;
    let longest = width.max(height).max(OUTPUT_SIDE);
    let out_width = (width * OUTPUT_SIDE / longest).max(1);
    let out_height = (height * OUTPUT_SIDE / longest).max(1);
    let mut luminance = vec![0; (out_width * out_height) as usize];
    // Area-average every source pixel into its output cell. Point sampling aliased
    // dense screenshots and thin terminal line gaps into broken modules.
    for y in 0..out_height {
        let top = y * height / out_height;
        let bottom = ((y + 1) * height / out_height).max(top + 1);
        for x in 0..out_width {
            let left = x * width / out_width;
            let right = ((x + 1) * width / out_width).max(left + 1);
            let mut sum = 0_u64;
            for source_y in top..bottom {
                for source_x in left..right {
                    let source = ((u64::from(source_y) * u64::from(width) + u64::from(source_x))
                        * channels) as usize;
                    sum += u64::from(composited_luma(&decoded[source..], channels as usize));
                }
            }
            let count = u64::from(bottom - top) * u64::from(right - left);
            luminance[(y * out_width + x) as usize] = (sum / count) as u8;
        }
    }
    Ok(QrImage {
        width: out_width,
        height: out_height,
        luminance,
    })
}

/// Grey level of one pixel, composited over white so transparent areas read as quiet zone.
fn composited_luma(pixel: &[u8], channels: usize) -> u32 {
    let luma = if channels <= 2 {
        u32::from(pixel[0])
    } else {
        (u32::from(pixel[0]) + 2 * u32::from(pixel[1]) + u32::from(pixel[2])) / 4
    };
    let alpha = if channels == 2 || channels == 4 {
        u32::from(pixel[channels - 1])
    } else {
        255
    };
    (luma * alpha + 255 * (255 - alpha)) / 255
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen(js_name = decodeQrImage)]
pub fn wasm_decode_qr_image(
    bytes: Vec<u8>,
    mime: String,
) -> Result<wasm_bindgen::JsValue, wasm_bindgen::JsValue> {
    use wasm_bindgen::JsValue;
    let mut decoded =
        decode_qr_image(bytes, mime).map_err(|_| JsValue::from_str("QR image rejected"))?;
    let object = js_sys::Object::new();
    let result = (|| {
        js_sys::Reflect::set(&object, &"width".into(), &decoded.width.into())?;
        js_sys::Reflect::set(&object, &"height".into(), &decoded.height.into())?;
        js_sys::Reflect::set(
            &object,
            &"luminance".into(),
            &js_sys::Uint8Array::from(decoded.luminance.as_slice()),
        )?;
        Ok(object.into())
    })();
    decoded.luminance.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageBuffer, ImageEncoder, Luma};

    fn png() -> Vec<u8> {
        let mut bytes = Vec::new();
        image::codecs::png::PngEncoder::new(&mut bytes)
            .write_image(&[0, 255, 255, 0], 2, 2, ColorType::L8.into())
            .unwrap();
        bytes
    }

    #[test]
    fn raster_only_content_and_mime_policy() {
        let decoded = decode_qr_image(png(), "image/png".into()).unwrap();
        assert_eq!(decoded.luminance, vec![0, 255, 255, 0]);
        assert!(decode_qr_image(png(), "image/jpeg".into()).is_err());
        assert!(decode_qr_image(png(), "image/svg+xml".into()).is_err());
        assert!(decode_qr_image(
            b"<svg><image href='file:///etc/passwd'/></svg>".to_vec(),
            "image/png".into()
        )
        .is_err());
        assert!(decode_qr_image(b"https://evil.example/image.png".to_vec(), "".into()).is_err());
        assert!(decode_qr_image(b"GIF89a".to_vec(), "image/png".into()).is_err());
        assert!(decode_qr_image(vec![0; MAX_QR_IMAGE_BYTES + 1], "".into()).is_err());
        let mut truncated = png();
        truncated.truncate(35);
        assert!(decode_qr_image(truncated, "".into()).is_err());
    }

    #[test]
    fn dimension_bombs_fail_before_output_allocation() {
        let image = ImageBuffer::<Luma<u8>, _>::from_pixel(1, MAX_SIDE + 1, Luma([0]));
        let mut bytes = Vec::new();
        image::codecs::png::PngEncoder::new(&mut bytes)
            .write_image(
                image.as_raw(),
                image.width(),
                image.height(),
                ColorType::L8.into(),
            )
            .unwrap();
        assert!(decode_qr_image(bytes, "image/png".into()).is_err());
    }

    #[test]
    fn transparent_pixels_are_composited_and_jpeg_is_supported() {
        let mut bytes = Vec::new();
        image::codecs::png::PngEncoder::new(&mut bytes)
            .write_image(&[0, 0, 0, 0, 0, 0, 0, 255], 2, 1, ColorType::Rgba8.into())
            .unwrap();
        assert_eq!(
            decode_qr_image(bytes, "".into()).unwrap().luminance,
            vec![255, 0]
        );
        let mut jpeg = Vec::new();
        image::codecs::jpeg::JpegEncoder::new(&mut jpeg)
            .write_image(&[255; 12], 2, 2, ColorType::Rgb8.into())
            .unwrap();
        assert_eq!(decode_qr_image(jpeg, "image/jpeg".into()).unwrap().width, 2);
    }

    #[test]
    fn jpeg_metadata_is_inert_and_cannot_replace_image_pixels() {
        let mut jpeg = Vec::new();
        image::codecs::jpeg::JpegEncoder::new(&mut jpeg)
            .write_image(&[255; 12], 2, 2, ColorType::Rgb8.into())
            .unwrap();
        let expected = decode_qr_image(jpeg.clone(), "image/jpeg".into()).unwrap();
        let metadata =
            b"Exif\0\0file:///etc/passwd https://evil.example/lookup?invite=secret <script>";
        let mut tagged = jpeg[..2].to_vec();
        tagged.extend_from_slice(&[0xff, 0xe1]);
        tagged.extend_from_slice(&((metadata.len() + 2) as u16).to_be_bytes());
        tagged.extend_from_slice(metadata);
        tagged.extend_from_slice(&jpeg[2..]);
        let result = decode_qr_image(tagged, "image/jpeg".into()).unwrap();
        assert_eq!(
            (result.width, result.height),
            (expected.width, expected.height)
        );
        assert_eq!(result.luminance, expected.luminance);
    }

    #[test]
    fn large_images_are_area_averaged_rather_than_point_sampled() {
        // A 1-pixel checkerboard at 2x the output side must average to mid grey;
        // point sampling would have returned only black or only white.
        let side = OUTPUT_SIDE * 2;
        let image = ImageBuffer::<Luma<u8>, _>::from_fn(side, side, |x, y| {
            Luma([if (x + y) % 2 == 0 { 0 } else { 255 }])
        });
        let mut bytes = Vec::new();
        image::codecs::png::PngEncoder::new(&mut bytes)
            .write_image(image.as_raw(), side, side, ColorType::L8.into())
            .unwrap();
        let decoded = decode_qr_image(bytes, "image/png".into()).unwrap();
        assert_eq!((decoded.width, decoded.height), (OUTPUT_SIDE, OUTPUT_SIDE));
        assert!(decoded
            .luminance
            .iter()
            .all(|value| (126..=128).contains(value)));
    }

    #[test]
    fn hostile_mutations_never_panic() {
        let valid = png();
        for index in 0..valid.len() {
            let mut mutated = valid.clone();
            mutated[index] ^= 0xff;
            let _ = decode_qr_image(mutated, "".into());
        }
    }
}
