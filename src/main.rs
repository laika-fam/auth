//! who up authorizing they accounts

mod endpoints;
mod model;

pub(crate) use model::Result;

use crate::endpoints::authorize;
use crate::endpoints::callback;
use crate::endpoints::jwks;
use crate::endpoints::openid_config;
use crate::model::AuthCode;
use crate::model::Jwks;
use crate::model::Session;
use axum::Router;
use axum::routing::get;
use core::ops::Deref;
use std::fmt::Debug;
use std::net::Ipv6Addr;
use std::str::FromStr;
use std::sync::Arc;

pub(crate) const BINCODE_CONFIG: bincode_next::config::Configuration<
    bincode_next::config::LittleEndian,
    bincode_next::config::Fixint,
> = bincode_next::config::standard()
    .with_little_endian()
    .with_fixed_int_encoding();

pub(crate) const EXTREMELY_LOUD_INCORRECT_BUZZER: &str = "[\u{1d404}\u{1d417}\u{1d413}\u{1d411}\u{1d404}\u{1d40c}\u{1d404}\u{1d40b}\u{1d418} \u{1d40b}\u{1d40e}\u{1d414}\u{1d403} \u{1d408}\u{1d40d}\u{1d402}\u{1d40e}\u{1d411}\u{1d411}\u{1d404}\u{1d402}\u{1d413} \u{1d401}\u{1d414}\u{1d419}\u{1d419}\u{1d404}\u{1d411}]";

#[derive(Clone)]
struct AppState(pub(crate) Arc<AppStateInner>);

pub(crate) type MokaKV<K, V> = moka::future::Cache<K, V>;

struct AppStateInner {
    pub http: reqwest::Client,
    pub issuer: Box<str>,
    pub keys: Jwks,
    pub sessions: MokaKV<uuid::Uuid, Arc<Session>>,
    pub auth_codes: MokaKV<uuid::Uuid, AuthCode>,
    pub google_client_id: Box<str>,
    pub google_client_secret: Box<str>,
}

fn assert_var<T>(var: &str) -> T
where
    T: FromStr,
    <T as FromStr>::Err: Debug,
{
    std::env::var(var)
        .expect(&format!("need ${var}"))
        .parse()
        .expect(&format!("malformed ${var}"))
}

impl AppState {
    pub async fn new() -> Self {
        Self(Arc::new(AppStateInner {
            http: reqwest::Client::new(),
            issuer: assert_var::<String>("ISSUER").into_boxed_str(),
            sessions: moka::future::Cache::new(100_000),
            keys: Jwks::new().await,
            auth_codes: moka::future::Cache::builder()
                .max_capacity(100_000)
                .time_to_live(std::time::Duration::from_secs(assert_var("AUTH_CODE_TTL")))
                .build(),
            google_client_id: assert_var::<String>("GOOGLE_CLIENT_ID").into_boxed_str(),
            google_client_secret: assert_var::<String>("GOOGLE_CLIENT_SECRET").into_boxed_str(),
        }))
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

#[tokio::main]
async fn main() {
    let app_state = AppState::new().await;
    let app = Router::new()
        .route("/robots.txt", get(robots))
        .route("/ping", get(ping))
        .route("/.well-known/openid-configuration", get(openid_config::get))
        .route("/jwks.json", get(jwks::get))
        .route("/authorize", get(authorize::get))
        .nest("/oauth/cb", callback::router())
        .with_state(app_state);

    let port = std::env::var("PORT")
        .unwrap_or(String::from("1989"))
        .parse::<u16>()
        .expect("$PORT not valid u16 port");

    let listener = tokio::net::TcpListener::bind((Ipv6Addr::UNSPECIFIED, port))
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}
