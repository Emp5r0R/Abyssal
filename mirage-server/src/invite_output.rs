//! One-shot invite presentation. QR output never falls back to disclosing text,
//! and text appears only when its own setting allows it.

use qrcode::{Color, EcLevel, QrCode};
use std::{
    env,
    io::{self, Write},
};
use zeroize::Zeroizing;

/// Which presentations of each boot invite reach the terminal. Both by default,
/// so an operator can scan the QR or copy the code from the same output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct InviteOutputMode {
    pub(super) qr: bool,
    pub(super) text: bool,
}

impl InviteOutputMode {
    #[cfg(test)]
    pub(super) const QR_AND_TEXT: Self = Self {
        qr: true,
        text: true,
    };
    #[cfg(test)]
    pub(super) const QR_ONLY: Self = Self {
        qr: true,
        text: false,
    };
    #[cfg(test)]
    pub(super) const TEXT_ONLY: Self = Self {
        qr: false,
        text: true,
    };

    pub(super) fn from_env() -> Result<Self, String> {
        let qr = read_setting("ABYSSAL_INVITE_QR_ENABLED")?;
        let text = read_setting("ABYSSAL_INVITE_TEXT_ENABLED")?;
        Self::parse(qr.as_deref(), text.as_deref())
    }

    fn parse(qr: Option<&str>, text: Option<&str>) -> Result<Self, String> {
        let mode = Self {
            qr: parse_flag("ABYSSAL_INVITE_QR_ENABLED", qr)?,
            text: parse_flag("ABYSSAL_INVITE_TEXT_ENABLED", text)?,
        };
        if !mode.qr && !mode.text {
            return Err(
                "ABYSSAL_INVITE_QR_ENABLED and ABYSSAL_INVITE_TEXT_ENABLED cannot both be false"
                    .to_owned(),
            );
        }
        Ok(mode)
    }
}

fn read_setting(key: &str) -> Result<Option<String>, String> {
    match env::var(key) {
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(invalid_setting(key)),
    }
}

fn parse_flag(key: &str, value: Option<&str>) -> Result<bool, String> {
    match value {
        None | Some("true") => Ok(true),
        Some("false") => Ok(false),
        _ => Err(invalid_setting(key)),
    }
}

fn invalid_setting(key: &str) -> String {
    format!("{key} must be exactly true or false")
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
    fn default_prints_qr_and_text_and_each_can_be_turned_off() {
        assert_eq!(
            InviteOutputMode::parse(None, None).unwrap(),
            InviteOutputMode::QR_AND_TEXT
        );
        assert_eq!(
            InviteOutputMode::parse(Some("true"), Some("false")).unwrap(),
            InviteOutputMode::QR_ONLY
        );
        assert_eq!(
            InviteOutputMode::parse(Some("false"), None).unwrap(),
            InviteOutputMode::TEXT_ONLY
        );
        assert_eq!(
            InviteOutputMode::parse(Some("false"), Some("false")).unwrap_err(),
            "ABYSSAL_INVITE_QR_ENABLED and ABYSSAL_INVITE_TEXT_ENABLED cannot both be false"
        );
        for input in ["", "1", "0", "TRUE", "False", " false", "true\n", "secret"] {
            assert_eq!(
                InviteOutputMode::parse(Some(input), None).unwrap_err(),
                invalid_setting("ABYSSAL_INVITE_QR_ENABLED")
            );
            assert_eq!(
                InviteOutputMode::parse(None, Some(input)).unwrap_err(),
                invalid_setting("ABYSSAL_INVITE_TEXT_ENABLED")
            );
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
