//! One-shot invite presentation. QR output never falls back to disclosing text.

use qrcode::{Color, EcLevel, QrCode};
use std::{
    env,
    io::{self, Write},
};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum InviteOutputMode {
    Qr,
    Text,
}

impl InviteOutputMode {
    pub(super) fn from_env() -> Result<Self, String> {
        match env::var("ABYSSAL_INVITE_QR_ENABLED") {
            Ok(value) => Self::parse(Some(&value)),
            Err(env::VarError::NotPresent) => Self::parse(None),
            Err(env::VarError::NotUnicode(_)) => Err(Self::invalid_setting()),
        }
    }

    fn parse(value: Option<&str>) -> Result<Self, String> {
        match value {
            None | Some("true") => Ok(Self::Qr),
            Some("false") => Ok(Self::Text),
            _ => Err(Self::invalid_setting()),
        }
    }

    fn invalid_setting() -> String {
        "ABYSSAL_INVITE_QR_ENABLED must be exactly true or false".to_owned()
    }
}

pub(super) fn write_qr<W: Write>(output: &mut W, deep_link: &str) -> io::Result<()> {
    if deep_link.is_empty() || deep_link.len() > abyssal_invite::MAX_ENCODED_INVITE_TEXT_BYTES {
        return Err(io::Error::other("invite QR input exceeds limits"));
    }
    let code = QrCode::with_error_correction_level(deep_link.as_bytes(), EcLevel::M)
        .map_err(|_| io::Error::other("invite QR encoding failed"))?;
    let width = code.width();
    let mut colors = code.into_colors();
    let modules = Zeroizing::new(
        colors
            .iter()
            .map(|color| *color == Color::Dark)
            .collect::<Vec<bool>>(),
    );
    // Clear the owned library matrix; internal encoder copies remain outside
    // our zeroization control, just like terminal/OS output buffers.
    colors.fill(Color::Light);
    std::hint::black_box(&mut colors);
    let size = width + 8;
    let dark = |x: usize, y: usize| {
        x >= 4 && y >= 4 && x < width + 4 && y < width + 4 && modules[(y - 4) * width + x - 4]
    };
    for y in (0..size).step_by(2) {
        let mut line = Zeroizing::new(String::with_capacity(size * 3 + 20));
        // Explicit black on white, including four quiet modules on every side.
        line.push_str("\x1b[30;47m");
        for x in 0..size {
            line.push(match (dark(x, y), dark(x, y + 1)) {
                (false, false) => ' ',
                (true, false) => '\u{2580}',
                (false, true) => '\u{2584}',
                (true, true) => '\u{2588}',
            });
        }
        line.push_str("\x1b[0m\n");
        output.write_all(line.as_bytes())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_qr_and_only_explicit_false_discloses_text() {
        assert_eq!(InviteOutputMode::parse(None).unwrap(), InviteOutputMode::Qr);
        assert_eq!(
            InviteOutputMode::parse(Some("true")).unwrap(),
            InviteOutputMode::Qr
        );
        assert_eq!(
            InviteOutputMode::parse(Some("false")).unwrap(),
            InviteOutputMode::Text
        );
        for input in ["", "1", "0", "TRUE", "False", " false", "true\n", "secret"] {
            let error = InviteOutputMode::parse(Some(input)).unwrap_err();
            assert_eq!(error, InviteOutputMode::invalid_setting());
        }
    }

    #[test]
    fn invalid_input_and_broken_output_fail_without_text_fallback() {
        for text in [
            String::new(),
            "x".repeat(abyssal_invite::MAX_ENCODED_INVITE_TEXT_BYTES + 1),
        ] {
            let mut out = Vec::new();
            assert!(write_qr(&mut out, &text).is_err());
            assert!(out.is_empty());
        }
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        assert_eq!(
            write_qr(&mut Broken, "abyssal:invite:test")
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
    }
}
