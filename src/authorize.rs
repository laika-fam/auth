use crate::EXTREMELY_LOUD_INCORRECT_BUZZER;
use crate::WithStatusCode;
use actix_web::Responder;
use actix_web::get;
use actix_web::http::StatusCode;
use actix_web::http::Uri;
use actix_web::web;
use anyhow::anyhow;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum PromptType {
    None,
    Consent,
}

#[derive(Debug, Deserialize)]
struct AuthorizeQuery {
    response_type: String,
    client_id: String,
    redirect_url: String,
    scope: String,
    state: Option<String>,
    code_challenge: String,
    code_challenge_method: String,
    prompt: Option<PromptType>,
}

#[get("/authorize")]
pub async fn authorize(query: web::Query<AuthorizeQuery>) -> crate::Result<impl Responder> {
    let query = query.into_inner();
    let Ok(redirect_url) = query.redirect_url.parse::<Uri>() else {
        return Err(anyhow!(EXTREMELY_LOUD_INCORRECT_BUZZER))
            .with_status_code(StatusCode::BAD_REQUEST);
    };
    if query.response_type != "code" || query.code_challenge_method != "S256" {
        return Err(anyhow!(EXTREMELY_LOUD_INCORRECT_BUZZER))
            .with_status_code(StatusCode::BAD_REQUEST);
    }

    Ok("todo")
}
