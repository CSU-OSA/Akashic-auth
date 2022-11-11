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
