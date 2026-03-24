//! who up authorizing they accounts

mod authorize;
mod keygen;
mod session;
mod util;

use crate::keygen::Jwks;
use actix_web::App;
use actix_web::HttpResponse;
use actix_web::HttpResponseBuilder;
use actix_web::HttpServer;
use actix_web::Responder;
use actix_web::ResponseError;
use actix_web::body::BoxBody;
use actix_web::get;
use actix_web::http::StatusCode;
use actix_web::http::header;
use actix_web::http::header::HeaderName;
use actix_web::http::header::HeaderValue;
use actix_web::http::header::TryIntoHeaderValue;
use actix_web::mime;
use actix_web::web;
use anyhow::Context;
use db::schema::jwk;
use diesel::ExpressionMethods;
use diesel::OptionalExtension;
use diesel::QueryDsl;
use diesel_async::AsyncPgConnection;
use diesel_async::RunQueryDsl;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use std::collections::HashMap;
use std::fmt::Formatter;

const EXTREMELY_LOUD_INCORRECT_BUZZER: &str = "[𝐄𝐗𝐓𝐑𝐄𝐌𝐄𝐋𝐘 𝐋𝐎𝐔𝐃 𝐈𝐍𝐂𝐎𝐑𝐑𝐄𝐂𝐓 𝐁𝐔𝐙𝐙𝐄𝐑]";

#[derive(Debug)]
struct AnyhowBridge(Box<(anyhow::Error, StatusCode)>);

impl core::fmt::Display for AnyhowBridge {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        self.0.0.fmt(f)
    }
}

impl<T> From<T> for AnyhowBridge
where
    T: Into<anyhow::Error>,
{
    fn from(value: T) -> Self {
        Self(Box::new((value.into(), StatusCode::INTERNAL_SERVER_ERROR)))
    }
}

impl ResponseError for AnyhowBridge {
    fn status_code(&self) -> StatusCode {
        self.0.1
    }

    fn error_response(&self) -> HttpResponse<BoxBody> {
        let mut res = HttpResponse::new(self.status_code());
        #[expect(
            clippy::unwrap_used,
            reason = "this is a constant valid ASCII header value"
        )]
        let mime = mime::APPLICATION_JSON.try_into_value().unwrap();
        res.headers_mut().insert(header::CONTENT_TYPE, mime);

        res.set_body(BoxBody::new(
            serde_json::json!({
                "error": format!("{self:#}"),
            })
            .to_string(),
        ))
    }
}

type Result<T> = core::result::Result<T, AnyhowBridge>;

pub(crate) trait WithStatusCode<T> {
    fn with_status_code(self, code: StatusCode) -> Result<T>;
}

impl<T> WithStatusCode<T> for anyhow::Result<T> {
    fn with_status_code(self, code: StatusCode) -> Result<T> {
        self.map_err(|err| AnyhowBridge(Box::new((err, code))))
    }
}

struct AppData {
    db: deadpool::managed::Pool<AsyncDieselConnectionManager<AsyncPgConnection>>,
    jwks: Jwks,
    http: reqwest::Client,
    issuer: Box<str>,
    sessions: HashMap<uuid::Uuid, session::Session>,
    google_client_id: Box<str>,
}

type DatabaseConnection =
    deadpool::managed::Object<AsyncDieselConnectionManager<AsyncPgConnection>>;

#[get("/robots.txt")]
pub async fn robots() -> &'static str {
    include_str!("robots.txt")
}

#[get("/ping")]
async fn ping() -> impl Responder {
    "pong"
}

#[get("/.well-known/openid-configuration")]
async fn openid_config(data: web::Data<AppData>) -> impl Responder {
    HttpResponseBuilder::new(StatusCode::OK)
        .insert_header(
            const {
                (
                    HeaderName::from_static("cache-control"),
                    HeaderValue::from_static("no-store"),
                )
            },
        )
        .json(serde_json::json!({
            "issuer": data.issuer,
            "authorization_endpoint": format!("{}/authorize", data.issuer),
            "token_endpoint": format!("{}/token", data.issuer),
            "userinfo_endpoint": format!("{}/userinfo", data.issuer),
            "jwks_uri": format!("{}/jwks.json", data.issuer),
            "scopes_supported": [
                "openid",
                "profile",
                "email",
            ],
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "token_endpoint_auth_methods_supported": ["none", "client_secret_basic"],
            "code_challenge_methods_supported": ["S256"],
            "claims_supported": ["sub", "iss", "aud", "exp", "iat", "name", "email"],
        }))
}

#[get("/jwks.json")]
async fn jwks_endpoint(data: web::Data<AppData>) -> Result<impl Responder> {
    let mut public = serde_json::to_value(&data.jwks.public)?;
    let public_obj = public.as_object_mut().unwrap();
    public_obj.insert("alg".into(), "RS256".into());
    public_obj.insert("use".into(), "sig".into());

    Ok(HttpResponseBuilder::new(StatusCode::OK)
        .insert_header(
            const {
                (
                    HeaderName::from_static("cache-control"),
                    HeaderValue::from_static("no-store"),
                )
            },
        )
        .json(serde_json::json!({
            "keys": [
                public_obj,
            ],
        })))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // if this fails (i.e. railway deployment, not local), meh
    let _ = dotenvy::dotenv();

    let port = std::env::var("PORT")
        .unwrap_or(String::from("1989"))
        .parse::<u16>()
        .context("$PORT not valid u16 port")?;

    let db_url = std::env::var("DATABASE_URL").context("need $DATABASE_URL")?;
    let config = AsyncDieselConnectionManager::<AsyncPgConnection>::new(&db_url);
    let db_pool = deadpool::managed::Pool::builder(config).build()?;

    let mut one_conn = db_pool.get().await?;
    let jwks = match jwk::table
        .select(jwk::key_data)
        .filter(jwk::id.eq("driving in my car"))
        .first::<serde_json::Value>(&mut one_conn)
        .await
        .optional()?
    {
        None => {
            let keys = keygen::generate();
            diesel::insert_into(jwk::table)
                .values((
                    jwk::id.eq("current"),
                    jwk::key_data.eq(serde_json::to_value(&keys)?),
                ))
                .on_conflict_do_nothing()
                .execute(&mut one_conn)
                .await?;
            keys
        }
        Some(stored) => serde_json::from_value(stored)?,
    };

    let app_data = web::Data::new(AppData {
        db: db_pool,
        jwks,
        http: reqwest::Client::new(),
        issuer: std::env::var("ISSUER")
            .context("need $ISSUER")?
            .into_boxed_str(),
        sessions: Default::default(),
        google_client_id: std::env::var("GOOGLE_CLIENT_ID")
            .expect("need $GOOGLE_CLIENT_ID")
            .into_boxed_str(),
    });

    let server = HttpServer::new(move || {
        App::new()
            .app_data(app_data.clone())
            .service(robots)
            .service(ping)
            .service(jwks_endpoint)
            .service(authorize::authorize)
    })
    .bind(("::", port))
    .with_context(|| format!("bind to port {port}"))?;

    eprintln!("ok, alive on port {port}...");

    Ok(server.run().await?)
}
