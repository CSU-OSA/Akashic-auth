use std::collections::HashMap;
use std::convert::Infallible;

#[cfg(feature = "builtin-casbin")]
use crate::{ADAPTER, MODEL};
#[cfg(feature = "builtin-casbin")]
use casbin::{CoreApi, Enforcer};

use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use log::{debug, error};
use reqwest::header::HeaderValue;
use warp::hyper::StatusCode;
use warp::reject::Reject;
use warp::{reject, reply, Rejection, Reply};

use crate::entity::CasdoorUser;
use crate::response::{ActiveResponse, TokenResponse};
use crate::{CLIENT, CONFIG};

#[derive(Debug)]
struct CustomRejection {
    msg: String,
}

impl Reject for CustomRejection {}

/// Parse jwt token to casdoor user entity.
fn parse_jwt_token(token: &str) -> Result<CasdoorUser, Box<dyn std::error::Error>> {
    let res = jsonwebtoken::decode::<CasdoorUser>(
        token,
        &DecodingKey::from_rsa_pem(CONFIG.jwt_pub_key.as_bytes())?,
        &Validation::new(Algorithm::RS256),
    )?;
    Ok(res.claims)
}

// Authorization
#[cfg(feature = "builtin-casbin")]
async fn enforce(sub: &str, path: String, method: String) -> Result<bool, Rejection> {
    let model = MODEL.get().ok_or(reject::custom(CustomRejection {
        msg: "Get permission model from memory failed (None Model)".to_string(),
    }))?;
    let adapter = ADAPTER.get().ok_or(reject::custom(CustomRejection {
        msg: "Get permission adapter from memory failed (None Adapter)".to_string(),
    }))?;
    let enforcer = Enforcer::new(model.clone(), adapter.clone())
        .await
        .map_err(|err| {
            error!("{}", err);
            reject::custom(CustomRejection {
                msg: "Build enforcer from permission model and adapter failed".to_string(),
            })
        })?;

    let res = enforcer
        .enforce((sub, path, method.to_lowercase()))
        .map_err(|err| {
            error!("{}", err);
            reject::custom(CustomRejection {
                msg: "Enforce permission controll failed".to_string(),
            })
        })?;

    Ok(res)
}

// Authorization
#[cfg(not(feature = "builtin-casbin"))]
async fn enforce(token: &str, path: String, method: String) -> Result<bool, Rejection> {
    let mut body = HashMap::new();
    body.insert(
        "id",
        format!("{}/{}", CONFIG.org_name, CONFIG.permission_name),
    );
    body.insert("v1", path);
    body.insert("v2", method.to_lowercase());

    let resp = CLIENT
        .post(format!("{}/api/enforce", CONFIG.endpoint))
        .json(&body)
        .header("Content-Type", "text/plain")
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .map_err(|err| {
            error!("{}", err);
            reject::custom(CustomRejection {
                msg: "Request for casdoor api \"/api/enforce\" failed".to_string()
            })
        })?;
    let res = resp
        .text()
        .await
        .map(|s| s.parse::<bool>())
        .map_err(|err| {
            error!("{}", err);
            reject::custom(CustomRejection { 
                msg: "Deserialize response from casdoor api \"/api/enforce\" to text failed".to_string() 
            })
        })?
        .map_err(|err| {
            error!("{}", err);
            reject::custom(CustomRejection { 
                msg: "Parse text to bool type failed".to_string() 
            })
        })?;

    Ok(res)
}

/// Send code to casdoor api and return access_token if successful.
/// Return FORBIDDEN if login failed.
pub async fn handle_login(query: HashMap<String, String>) -> Result<impl Reply, Rejection> {
    let code = query.get("code").ok_or(reject::reject())?;
    let resp = CLIENT
        .post(format!("{}/api/login/oauth/access_token?grant_type=authorization_code&client_id={}&client_secret={}&code={}", CONFIG.endpoint, CONFIG.client_id, CONFIG.client_secret, code))
        .send()
        .await
        .map_err(|err| {
            error!("{}", err);
            reject::custom(CustomRejection { 
                msg: "Request for casdoor api \"/api/login/oauth/access_token\" failed".to_string()
            })
        })?
        .json::<TokenResponse>()
        .await
        .map_err(|_| reject::reject())?;
    let token = resp.access_token;
    let mut resp = HashMap::new();
    resp.insert("token", token.clone());
    match parse_jwt_token(&token) {
        Ok(_) => Ok(reply::json(&resp)),
        Err(_) => Err(reject::reject()),
    }
}

/// Every request to microservices behind will be handled in this function. 
/// The function will do authentication first to confirm the access_token is valid. 
/// Then it will do authorization using casbin to check the request permission. 
/// (sub, obj, act) <-> (owner/name, request path, lowercase request method)
pub async fn handle_authenticate(
    token: Option<String>,
    method: String,
    path: String,
) -> Result<impl Reply, Rejection> {

    let token = if method == "OPTIONS" {
        // CORS precheck request
        return Ok(reply::with_status(reply::reply(), StatusCode::OK).into_response())
    } else {
        token.ok_or(reject::reject())?
    };

    let msg = format!("{{token: {}, method: {}, path: {}}}", token, method, path);
    debug!("Authenticate inbound request: {}", msg);

    // Remove url params
    let path = path.split('?').collect::<Vec<&str>>().get(0)
        .ok_or(reject::custom(CustomRejection { msg: "Split path failed".to_string() }))?
        .to_string();

    // Authentication

    let resp = CLIENT.post(format!("{}/api/login/oauth/introspect?token={}&token_type_hint=access_token&client_id={}&client_secret={}", CONFIG.endpoint, token, CONFIG.client_id, CONFIG.client_secret))
        .send()
        .await
        .map_err(|err| {
            error!("{}", err);
            reject::custom(CustomRejection {
                msg: "Request for casdoor api \"/api/login/oauth/introspect\" failed".to_string()
            })
        })?
        .json::<ActiveResponse>()
        .await
        .map_err(|err| {
            error!("{}", err);
            reject::custom(CustomRejection {
                msg: "Deserialize response from casdoor api \"/api/login/oauth/introspect\" failed".to_string()
            })
        })?;

    debug!("{:#?}", resp);

    if !resp.active {
        return Ok(reply::with_status(reply::reply(), StatusCode::UNAUTHORIZED).into_response());
    }

    // Authorization

    // User's organization and name should not be changed by updating profile.
    // So that a valid access_token can always get the valid id (owner/name).
    // Token should be valid when enforce permission control since authentication completed.
    let user = parse_jwt_token(&token).map_err(|err| {
        error!("{}", err);
        reject::custom(CustomRejection {
            msg: "Unexpected token when enforce permission control".to_string(),
        })
    })?;
    let sub = format!("{}/{}", user.owner, user.name);

    if enforce(if cfg!(feature = "builtin-casbin") { &sub } else { &token }, path, method).await? {
        let mut response = reply::with_status(reply::reply(), StatusCode::OK).into_response();
        let remote_user = HeaderValue::from_str(&sub).map_err(|err| {
            error!("{}", err);
            reject::custom(CustomRejection { msg: "Add Remote-User header failed".to_string() })
        })?;
        response.headers_mut().append("Remote-User", remote_user);
        Ok(response)
    } else {
        Ok(reply::with_status(reply::reply(), StatusCode::FORBIDDEN).into_response())
    }
}

/// Global exception handler function.
/// It is always an empty response with FORBIDDEN http status.
pub async fn err_handle(err: Rejection) -> Result<impl Reply, Infallible> {
    if let Some(e) = err.find::<CustomRejection>() {
        error!("{}", e.msg);
        // Project uses Cargo to build so the environment variable is always valid
        Ok(reply::with_status(reply::html(format!("[{}] {}", env!("CARGO_PKG_NAME") ,e.msg.clone())), StatusCode::BAD_GATEWAY))
    } else {
        Ok(reply::with_status(reply::html("".to_string()), StatusCode::FORBIDDEN))
    }
}
