use actix_web::HttpResponse;
use actix_web::HttpResponseBuilder;
use actix_web::http::StatusCode;
use actix_web::http::header::HeaderName;
use actix_web::http::header::HeaderValue;

pub fn found_redirect(location: &str) -> HttpResponse {
    HttpResponseBuilder::new(StatusCode::FOUND)
        .insert_header((
            const { HeaderName::from_static("location") },
            // safety: url crate enforces no NUL
            unsafe { HeaderValue::from_str(location).unwrap_unchecked() },
        ))
        .finish()
}
