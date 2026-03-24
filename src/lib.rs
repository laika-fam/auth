//! who up authorizing they accounts

mod endpoints;
mod error;
mod keys;

pub(crate) use error::Result;

use crate::endpoints::authorize;
use crate::endpoints::jwks;
use crate::endpoints::openid_config;
use crate::keys::Jwks;
use axum::routing::get;
use axum::Router;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;
use tower_service::Service;
use web_sys::wasm_bindgen::convert::Upcast;
use worker::wasm_bindgen::JsCast;
use worker::wasm_bindgen::UnwrapThrowExt;

#[derive(Clone)]
struct AppState(pub(crate) Arc<AppStateInner>);

struct AppStateInner {
    pub(crate) issuer: Box<str>,
    pub(crate) google_client_id: Box<str>,
    pub(crate) sessions: worker::KvStore,
    pub(crate) keys: worker::KvStore,
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
        }))
    }

    async fn keys(&self) -> Jwks {
        if let Some(jwks) = self
            .keys
            .get("driving in my car")
            .json::<Jwks>()
            .await
            .unwrap_throw()
        {
            jwks
        } else {
            {
                let jwks = Jwks::new().await;
                self.keys
                    .put("driving in my car", &jwks)
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
