use std::collections::HashMap;
use std::convert::Infallible;

use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use log::debug;
use warp::hyper::StatusCode;
use warp::{reject, reply, Rejection, Reply};

use crate::entity::CasdoorUser;
use crate::response::{ActiveResponse, TokenResponse};
use crate::CONFIG;

/// Parse jwt token to casdoor user entity.
fn parse_jwt_token(token: &str) -> Result<CasdoorUser, Box<dyn std::error::Error>> {
    let res = jsonwebtoken::decode::<CasdoorUser>(
        token,
        &DecodingKey::from_rsa_pem(CONFIG.jwt_pub_key.as_bytes())?,
        &Validation::new(Algorithm::RS256),
    )?;
    Ok(res.claims)
}

/// Send code to casdoor api and return access_token if successful.
/// Return FORBIDDEN if login failed.
pub async fn handle_login(query: HashMap<String, String>) -> Result<impl Reply, Rejection> {
    let code = query.get("code").ok_or(reject::reject())?;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/login/oauth/access_token?grant_type=authorization_code&client_id={}&client_secret={}&code={}", CONFIG.endpoint, CONFIG.client_id, CONFIG.client_secret, code))
        .send()
        .await
        .map_err(|_| reject::reject())?
        .json::<TokenResponse>()
        .await
        .map_err(|_| reject::reject())?;
    let token = resp.access_token;
    let mut resp = HashMap::new();
    resp.insert("token", token.clone());
    match parse_jwt_token(&token) {
        Ok(_) => Ok(reply::json(&resp)),
        Err(_) => return Err(reject::reject()),
    }
}

pub async fn handle_authenticate(
    token: String,
    method: String,
    path: String,
) -> Result<impl Reply, Rejection> {
    let msg = format!("{{token: {}, method: {}, path: {}}}", token, method, path);
    debug!("Authenticate inbound request: {}", msg);

    let client = reqwest::Client::new();

    // Authentication

    let resp = client.post(format!("{}/api/login/oauth/introspect?token={}&token_type_hint=access_token&client_id={}&client_secret={}", CONFIG.endpoint, token, CONFIG.client_id, CONFIG.client_secret))
        .send()
        .await
        .map_err(|_| reject::reject())?
        .json::<ActiveResponse>()
        .await
        .map_err(|_| reject::reject())?;

    debug!("{:#?}", resp);

    if !resp.active {
        return Ok(reply::with_status(reply::reply(), StatusCode::UNAUTHORIZED));
    }

    // Authorization

    let mut body = HashMap::new();
    body.insert(
        "id",
        format!("{}/{}", CONFIG.org_name, CONFIG.permission_name),
    );
    body.insert("v1", path);
    body.insert("v2", method);

    let resp = client
        .post(format!("{}/api/enforce", CONFIG.endpoint))
        .json(&body)
        .header("Content-Type", "text/plain")
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .map_err(|_| reject::reject())?;
    let res = resp
        .text()
        .await
        .map(|s| s.parse::<bool>())
        .map_err(|_| reject::reject())?
        .map_err(|_| reject::reject())?;

    debug!("{:#?}, {}", body, res);

    if res {
        Ok(reply::with_status(reply::reply(), StatusCode::OK))
    } else {
        Ok(reply::with_status(reply::reply(), StatusCode::FORBIDDEN))
    }
}

/// Global exception handler function.
/// It is always an empty response with FORBIDDEN http status.
pub async fn err_handle(_err: Rejection) -> Result<impl Reply, Infallible> {
    Ok(warp::reply::with_status(
        warp::reply::reply(),
        StatusCode::FORBIDDEN,
    ))
}