//! who up authorizing they accounts

mod endpoints;
mod model;

pub(crate) use model::Result;

use crate::endpoints::authorize;
use crate::endpoints::jwks;
use crate::endpoints::openid_config;
use crate::model::Jwks;
use axum::routing::get;
use axum::Router;
use core::ops::Deref;
use std::sync::Arc;
use tower_service::Service as _;
use worker::wasm_bindgen::UnwrapThrowExt as _;

pub(crate) const BINCODE_CONFIG: bincode_next::config::Configuration<
    bincode_next::config::LittleEndian,
    bincode_next::config::Fixint,
> = bincode_next::config::standard()
    .with_little_endian()
    .with_fixed_int_encoding();

#[derive(Clone)]
struct AppState(pub(crate) Arc<AppStateInner>);

struct AppStateInner {
    pub(crate) issuer: Box<str>,
    pub(crate) google_client_id: Box<str>,
    pub(crate) sessions: worker::KvStore,
    pub(crate) keys: worker::KvStore,
    pub(crate) auth_codes: worker::KvStore,
    pub(crate) auth_code_ttl: u64,
}

impl AppState {
    fn new(env: worker::Env) -> Self {
        Self(Arc::new(AppStateInner {
            issuer: env
                .var("ISSUER")
                .unwrap_throw()
                .to_string()
                .into_boxed_str(),
            google_client_id: env
                .var("GOOGLE_CLIENT_ID")
                .unwrap_throw()
                .to_string()
                .into_boxed_str(),
            sessions: env.kv("AUTH_SESSIONS").unwrap_throw(),
            keys: env.kv("AUTH_KEYS").unwrap_throw(),
            auth_codes: env.kv("AUTH_AUTH_CODES").unwrap_throw(),
            auth_code_ttl: env
                .var("AUTH_CODE_TTL")
                .unwrap_throw()
                .to_string()
                .parse()
                .unwrap_throw(),
        }))
    }

    async fn keys(&self) -> Jwks {
        if let Some(jwks) = self
            .keys
            .get("driving in my car")
            .json::<serde_json::Value>()
            .await
            .unwrap_throw()
            .map(|v| serde_json::from_value(v).unwrap_throw())
        {
            jwks
        } else {
            {
                let jwks = Jwks::new().await;
                self.keys
                    .put(
                        "driving in my car",
                        // worker serialization glue doesn't work :(
                        serde_json::to_value(&jwks).unwrap_throw().to_string(),
                    )
                    .unwrap_throw()
                    .execute()
                    .await
                    .unwrap_throw();
                jwks
            }
        }
    }
}

impl Deref for AppState {
    type Target = AppStateInner;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

async fn robots() -> &'static str {
    include_str!("robots.txt")
}

async fn ping() -> &'static str {
    "pong"
}

fn router(env: worker::Env) -> Router {
    let app_state = AppState::new(env);

    Router::new()
        .route("/robots.txt", get(robots))
        .route("/ping", get(ping))
        .route("/.well-known/openid-configuration", get(openid_config::get))
        .route("/jwks.json", get(jwks::get))
        .route("/authorize", get(authorize::get))
        .with_state(app_state)
}

#[worker_macros::event(fetch)]
async fn fetch(
    req: worker::HttpRequest,
    env: worker::Env,
    _ctx: worker::Context,
) -> worker::Result<axum::http::Response<axum::body::Body>> {
    Ok(router(env).call(req).await?)
}
