//! HTTP surface assembly for the relay.
//!
//! Handlers remain owned by the protocol modules in `main.rs`; this module
//! owns route composition, static-client fallback, and transport middleware.

use super::*;

pub(super) fn router(state: AppState) -> Router {
    let account_routes = Router::new()
        .route("/v2/account/start", post(start_opaque_account))
        .route("/v2/account/finish", post(finish_opaque_account))
        .route("/v1/ws-ticket", post(issue_ws_ticket))
        .route("/v1/account/logout", post(logout_account))
        .layer(DefaultBodyLimit::max(ACCOUNT_BODY_LIMIT_BYTES));
    let attachment_upload_routes = Router::new().route("/v1/attachment", post(upload_attachment));
    let attachment_download_routes = Router::new()
        .route(
            "/v1/attachment/:id",
            get(download_attachment).delete(delete_attachment),
        )
        .route(
            "/v1/attachment/:id/complete",
            post(complete_attachment_claim),
        )
        .route("/v1/attachment/:id/claim", delete(release_attachment_claim));
    let attachment_routes = attachment_upload_routes.merge(attachment_download_routes);

    let web_origins = state.web_origins.clone();
    let mut app = Router::new()
        .route("/health", get(health))
        .route(
            release_admission::RELEASE_MANIFEST_ENDPOINT,
            get(release_manifest_endpoint),
        )
        .route(
            release_admission::RELEASE_SIGNATURE_ENDPOINT,
            get(release_signature_endpoint),
        )
        .merge(account_routes)
        .merge(attachment_routes)
        .route("/v1/ws", get(ws_handler))
        .route("/v1/*path", any(api_not_found))
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());

    if let Some(web_root) = resolve_web_root() {
        info!("serving Abyssal web client from {}", web_root.display());
        let index = web_root.join("index.html");
        app = app.fallback_service(
            ServeDir::new(web_root)
                .append_index_html_on_directories(true)
                .not_found_service(ServeFile::new(index)),
        );
    }

    let allowed_origins = web_origins
        .iter()
        .filter_map(|origin| HeaderValue::from_str(origin).ok())
        .collect::<Vec<_>>();
    if !allowed_origins.is_empty() {
        app = app.layer(
            CorsLayer::new()
                .allow_origin(allowed_origins)
                .allow_methods([Method::DELETE, Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers([
                    header::AUTHORIZATION,
                    header::CONTENT_TYPE,
                    header::HeaderName::from_static(ATTACHMENT_CLAIM_HEADER),
                ])
                .expose_headers([header::HeaderName::from_static(ATTACHMENT_CLAIM_HEADER)])
                .max_age(std::time::Duration::from_secs(600)),
        );
    }
    app.layer(middleware::from_fn(security_headers))
}

pub(super) async fn api_not_found() -> StatusCode {
    StatusCode::NOT_FOUND
}

pub(super) async fn release_manifest_endpoint(State(state): State<AppState>) -> Response {
    release_material_response(
        state.release_admission.manifest_bytes().await,
        "application/json",
    )
}

pub(super) async fn release_signature_endpoint(State(state): State<AppState>) -> Response {
    release_material_response(
        state.release_admission.signature_bytes().await,
        "application/octet-stream",
    )
}

fn release_material_response(body: Option<Vec<u8>>, content_type: &'static str) -> Response {
    match body {
        Some(body) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, content_type),
                (header::CACHE_CONTROL, "no-store"),
                (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            ],
            Body::from(body),
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

pub(super) const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' blob: data:; media-src 'self' blob:; connect-src 'self' https: wss: http://localhost:* http://127.0.0.1:* http://[::1]:* ws://localhost:* ws://127.0.0.1:* ws://[::1]:*; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; worker-src 'none'; manifest-src 'none'";
pub(super) const CACHE_CONTROL_POLICY: &str =
    "no-store, no-cache, no-transform, max-age=0, must-revalidate";

async fn security_headers(request: Request, next: Next) -> Response {
    let clear_site_data = request.uri().path() == "/v1/account/logout";
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(CACHE_CONTROL_POLICY),
    );
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(header::EXPIRES, HeaderValue::from_static("0"));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=63072000; includeSubDomains; preload"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static(
            "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), interest-cohort=()",
        ),
    );
    headers.insert(
        header::HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        header::HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("cross-origin"),
    );
    headers.insert(
        header::HeaderName::from_static("x-permitted-cross-domain-policies"),
        HeaderValue::from_static("none"),
    );
    headers.insert(
        header::HeaderName::from_static("x-robots-tag"),
        HeaderValue::from_static("noindex, noarchive, nosnippet"),
    );
    if clear_site_data {
        headers.insert(
            header::HeaderName::from_static("clear-site-data"),
            HeaderValue::from_static("\"cache\", \"cookies\", \"storage\""),
        );
    }
    response
}
