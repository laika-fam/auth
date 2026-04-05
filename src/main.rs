//! who up authorizing they accounts

mod endpoints;
mod model;
mod serde;

pub(crate) use model::Result;

use crate::endpoints::authorize;
use crate::endpoints::callback;
use crate::endpoints::jwks;
use crate::endpoints::openid_config;
use crate::endpoints::token;
use crate::endpoints::userinfo;
use crate::model::AccessToken;
use crate::model::AuthCode;
use crate::model::BackingOauthState;
use crate::model::Jwks;
use crate::model::Session;
use crate::model::ToFromAws as _;
use axum::Router;
use axum::routing::get;
use core::fmt::Debug;
use core::net::Ipv6Addr;
use core::ops::Deref;
use core::str::FromStr;
use std::sync::Arc;

pub(crate) const EXTREMELY_LOUD_INCORRECT_BUZZER: &str = "[\u{1d404}\u{1d417}\u{1d413}\u{1d411}\u{1d404}\u{1d40c}\u{1d404}\u{1d40b}\u{1d418} \u{1d40b}\u{1d40e}\u{1d414}\u{1d403} \u{1d408}\u{1d40d}\u{1d402}\u{1d40e}\u{1d411}\u{1d411}\u{1d404}\u{1d402}\u{1d413} \u{1d401}\u{1d414}\u{1d419}\u{1d419}\u{1d404}\u{1d411}]";

#[derive(Clone)]
struct AppState(pub(crate) Arc<AppStateInner>);

pub(crate) type MokaKV<K, V> = moka::future::Cache<K, V>;

struct AppStateInner {
    pub http: reqwest::Client,
    pub issuer: Box<str>,
    pub keys: Jwks,
    // if more providers, split this up
    pub backing_oauth_states: MokaKV<uuid::Uuid, BackingOauthState>,
    pub sessions: MokaKV<uuid::Uuid, Arc<Session>>,
    pub session_ttl: core::time::Duration,
    pub google_client_id: Box<str>,
    pub google_client_secret: Box<str>,
    pub auth_codes: MokaKV<uuid::Uuid, Arc<AuthCode>>,
    pub access_tokens: MokaKV<uuid::Uuid, Arc<AccessToken>>,
    pub access_token_ttl: core::time::Duration,
    // refresh tokens in redis
    pub refresh_token_ttl: core::time::Duration,
    pub redis: redis::Client,
}

fn assert_var<T>(var: &str) -> T
where
    T: FromStr,
    <T as FromStr>::Err: Debug,
{
    std::env::var(var)
        .unwrap_or_else(|_| panic!("need ${var}"))
        .parse()
        .unwrap_or_else(|_| panic!("malformed ${var}"))
}

impl AppState {
    pub async fn new() -> Self {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::v2026_01_12()).await;
        let aws = aws_sdk_s3::Client::new(&config);

        let keys = if let Ok(bucket_name) = std::env::var("AWS_S3_BUCKET_NAME") {
            if let Ok(Some(keys)) = Jwks::from_aws(&aws, &bucket_name).await {
                keys
            } else {
                let keys = Jwks::new().await;
                if keys.to_aws(&aws, &bucket_name).await.is_err() {
                    eprintln!(
                        "warning: couldn't save newly generated keys; they will not persist!"
                    );
                }
                keys
            }
        } else {
            eprintln!("warning: no mount path; keys will not persist!");

            Jwks::new().await
        };

        let session_ttl = core::time::Duration::from_secs(assert_var("SESSION_TTL"));
        let access_token_ttl = core::time::Duration::from_secs(assert_var("ACCESS_TOKEN_TTL"));

        Self(Arc::new(AppStateInner {
            http: reqwest::Client::new(),
            issuer: assert_var::<String>("ISSUER").into_boxed_str(),
            keys,
            backing_oauth_states: moka::future::Cache::builder()
                .max_capacity(10_000)
                .initial_capacity(100)
                .time_to_live(core::time::Duration::from_secs(assert_var(
                    "BACKING_OAUTH_STATE_TTL",
                )))
                .build(),
            sessions: moka::future::Cache::builder()
                .max_capacity(10_000)
                .initial_capacity(100)
                .time_to_live(session_ttl)
                .build(),
            session_ttl,
            google_client_id: assert_var::<String>("GOOGLE_CLIENT_ID").into_boxed_str(),
            google_client_secret: assert_var::<String>("GOOGLE_CLIENT_SECRET").into_boxed_str(),
            auth_codes: moka::future::Cache::builder()
                .max_capacity(10_000)
                .initial_capacity(100)
                .time_to_live(core::time::Duration::from_secs(assert_var("AUTH_CODE_TTL")))
                .build(),
            access_tokens: moka::future::Cache::builder()
                .max_capacity(10_000)
                .initial_capacity(100)
                .time_to_live(access_token_ttl)
                .build(),
            access_token_ttl,
            refresh_token_ttl: core::time::Duration::from_secs(assert_var("REFRESH_TOKEN_TTL")),
            #[expect(clippy::expect_used, reason = "we can crash if setup fails")]
            redis: redis::Client::open(assert_var::<String>("REDIS_URL"))
                .expect("connect to redis"),
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
        .route("/token", get(token::get))
        .route("/userinfo", get(userinfo::get))
        .layer(tower_cookies::CookieManagerLayer::new())
        .with_state(app_state);

    #[expect(clippy::expect_used, reason = "we cannot proceed without a valid port")]
    let port = std::env::var("PORT")
        .unwrap_or(String::from("1989"))
        .parse::<u16>()
        .expect("$PORT not valid u16 port");

    #[expect(clippy::unwrap_used, reason = "we cannot proceed without binding")]
    let listener = tokio::net::TcpListener::bind((Ipv6Addr::UNSPECIFIED, port))
        .await
        .unwrap();

    println!("serving on {port}...");

    #[expect(clippy::unwrap_used, reason = "never returns")]
    axum::serve(listener, app).await.unwrap();
}
