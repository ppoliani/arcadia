use crate::Arcadia;
use actix_web::{HttpResponse, web};
use arcadia_common::error::{Error, Result};
use arcadia_storage::models::user::{Claims, Login, LoginResponse};
use chrono::Duration;
use chrono::prelude::Utc;
use jsonwebtoken::{EncodingKey, Header, encode};

#[utoipa::path(
    post,
    path = "/api/login",
    responses(
        (status = 200, description = "Successfully logged in", body=LoginResponse),
    )
)]
pub async fn exec(arc: web::Data<Arcadia>, user_login: web::Json<Login>) -> Result<HttpResponse> {
    let user = arc.pool.find_user_with_password(&user_login).await?;

    if user.banned {
        return Err(Error::AccountBanned);
    }

    let mut token_expiration_date = Utc::now();
    let mut refresh_token = String::from("");
    if !user_login.remember_me {
        token_expiration_date += Duration::hours(1);
    } else {
        token_expiration_date += Duration::days(1);

        let refresh_token_expiration_date = Utc::now() + Duration::days(90);
        let refresh_token_claims = Claims {
            sub: user.id,
            exp: refresh_token_expiration_date.timestamp() as usize,
        };
        refresh_token = encode(
            &Header::default(),
            &refresh_token_claims,
            &EncodingKey::from_secret(arc.jwt_secret.as_bytes()),
        )
        .unwrap();
    }

    let token_claims = Claims {
        sub: user.id,
        exp: token_expiration_date.timestamp() as usize,
    };

    let token = encode(
        &Header::default(),
        &token_claims,
        &EncodingKey::from_secret(arc.jwt_secret.as_bytes()),
    )
    .unwrap();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "token": token,
        "refresh_token": refresh_token
    })))
}
