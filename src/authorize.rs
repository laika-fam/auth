use crate::AppData;
use crate::EXTREMELY_LOUD_INCORRECT_BUZZER;
use crate::WithStatusCode;
use crate::util::found_redirect;
use actix_web::HttpRequest;
use actix_web::Responder;
use actix_web::get;
use actix_web::http::StatusCode;
use actix_web::web;
use anyhow::Context;
use anyhow::anyhow;
use serde::Deserialize;
use url::Url;

struct ClientDef {}

static CLIENTS: phf::Map<&'static str, ClientDef> = phf::phf_map! {
    "test" => ClientDef {},
};

fn allowed(client_id: &str, redirect_url: &str) -> bool {
    // TODO: check redirect
    CLIENTS.contains_key(client_id)
}

#[derive(Debug, Deserialize, Copy, Clone, Hash, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum PromptType {
    None,
    Consent,
}

#[derive(Debug, Deserialize)]
struct AuthorizeQuery {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: Option<String>,
    code_challenge: String,
    code_challenge_method: String,
    prompt: Option<PromptType>,
}

#[get("/authorize")]
pub async fn authorize(
    data: web::Data<AppData>,
    request: HttpRequest,
    query: web::Query<AuthorizeQuery>,
) -> crate::Result<impl Responder> {
    let query = query.into_inner();
    let Ok(mut redirect_uri) = query.redirect_uri.parse::<url::Url>() else {
        return Err(anyhow!(EXTREMELY_LOUD_INCORRECT_BUZZER))
            .with_status_code(StatusCode::BAD_REQUEST);
    };

    if query.response_type == "code" && query.code_challenge_method == "S256" {
        return Err(anyhow!(EXTREMELY_LOUD_INCORRECT_BUZZER))
            .with_status_code(StatusCode::BAD_REQUEST);
    }

    if !allowed(&query.client_id, &query.redirect_uri) {
        return Err(anyhow!("GET OUT")).with_status_code(StatusCode::BAD_REQUEST);
    }

    let sid = request.cookie("sid");
    if let Some(sid) = sid
        && data.sessions.contains_key(
            &sid.value()
                .parse::<uuid::Uuid>()
                .context("bad sid")
                .with_status_code(StatusCode::BAD_REQUEST)?,
        )
    {
        todo!("can't handle existing sessions yet :(")
        // scope check
    }

    if query.prompt == Some(PromptType::None) {
        {
            let mut query_pairs = redirect_uri.query_pairs_mut();
            query_pairs.append_pair("error", "login_required");
            if let Some(ref state) = query.state {
                query_pairs.append_pair("state", state);
            }
        }
        return Ok(found_redirect(redirect_uri.as_str()));
    }

    let mut url = Url::parse("https://accounts.google.com/o/oauth2/v2/auth")
        .context("parse base google oauth url")?;
    {
        let mut query_pairs = url.query_pairs_mut();
        query_pairs.append_pair("access_type", "offline");
        query_pairs.append_pair("response_type", "code");
        query_pairs.append_pair("client_id", &data.google_client_id);
        query_pairs.append_pair("redirect_uri", &format!("{}/oauth/cb/goog", data.issuer));
        query_pairs.append_pair("scope", &query.scope);
        query_pairs.append_pair("prompt", "consent");
        query_pairs.append_pair(
            "state",
            &serde_json::to_string(&serde_json::json!({
                "client_id": data.google_client_id,
                "redirect_uri": query.redirect_uri,
                "state": query.state,
                "code_challenge": query.code_challenge,
                "scope": query.scope,

            }))
            .context("create oauth state string to goog")?,
        );
    }

    Ok(found_redirect(url.as_str()))
}
