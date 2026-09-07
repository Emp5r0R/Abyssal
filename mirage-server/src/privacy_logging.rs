//! Keep dependency request dumps outside the relay's diagnostic output.

use tracing::Metadata;
use tracing_subscriber::{filter::filter_fn, layer::SubscriberExt, util::SubscriberInitExt, Layer};

fn allowed_target(metadata: &Metadata<'_>) -> bool {
    let target = metadata.target();
    target == "mirage_server" || target.starts_with("mirage_server::")
}

pub(super) fn init() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mirage_server=info".into()),
        )
        .with(tracing_subscriber::fmt::layer().with_filter(filter_fn(allowed_target)))
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io,
        sync::{Arc, Mutex},
    };

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn verbose_configuration_cannot_enable_dependency_request_dumps() {
        for filter in [
            "trace",
            "mirage_server=trace,reqwest=trace,tower_http=trace,axum=trace",
        ] {
            let output = Capture::default();
            let writer = output.clone();
            let subscriber = tracing_subscriber::registry()
                .with(tracing_subscriber::EnvFilter::new(filter))
                .with(
                    tracing_subscriber::fmt::layer()
                        .without_time()
                        .with_ansi(false)
                        .with_writer(move || writer.clone())
                        .with_filter(filter_fn(allowed_target)),
                );
            tracing::subscriber::with_default(subscriber, || {
                tracing::info!(target: "mirage_server", "safe operational event");
                tracing::warn!(target: "mirage_server::transport", "safe rejection");
                tracing::error!(target: "reqwest", "SECRET_QUERY");
                tracing::warn!(target: "tower_http::trace", "SECRET_PATH");
                tracing::debug!(target: "axum::rejection", "SECRET_BODY");
                tracing::trace!(target: "hyper", "SECRET_HEADER");
                tracing::error!(target: "mirage_server_lookalike", "SECRET_LOOKALIKE");
                let span =
                    tracing::info_span!(target: "reqwest", "SECRET_SPAN", url = "SECRET_URL");
                let _entered = span.enter();
                tracing::warn!(target: "mirage_server::transport", "safe nested event");
            });
            let bytes = output.0.lock().unwrap();
            let text = std::str::from_utf8(&bytes).unwrap();
            assert!(text.contains("safe operational event"));
            assert!(text.contains("safe rejection"));
            assert!(text.contains("safe nested event"));
            assert!(!text.contains("SECRET"));
        }
    }
}
