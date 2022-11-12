use serde_derive::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub expires_in: u32,
    pub id_token: String,
    pub refresh_token: String,
    pub scope: String,
    pub token_type: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ActiveResponse {
    pub active: bool,
    pub aud: Option<Vec<String>>,
    pub client_id: Option<String>,
    pub exp: Option<i32>,
    pub iat: Option<i32>,
    pub iss: Option<String>,
    pub jti: Option<String>,
    pub nbf: Option<i32>,
    pub scope: Option<String>,
    pub sub: Option<String>,
    pub token_type: Option<String>,
    pub username: Option<String>,
}
