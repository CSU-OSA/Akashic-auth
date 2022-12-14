use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;

#[cfg(feature = "builtin-casbin")]
use sqlx::FromRow;

#[allow(dead_code)]
#[cfg(feature = "builtin-casbin")]
#[derive(Debug, FromRow)]
pub(crate) struct CasbinRule {
    pub ptype: String,
    pub v0: String,
    pub v1: String,
    pub v2: String,
    pub v3: String,
    pub v4: String,
    pub v5: String,
}

#[cfg(feature = "builtin-casbin")]
#[derive(Debug)]
pub(crate) struct NewCasbinRule<'a> {
    pub ptype: &'a str,
    pub v0: &'a str,
    pub v1: &'a str,
    pub v2: &'a str,
    pub v3: &'a str,
    pub v4: &'a str,
    pub v5: &'a str,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub address: String,
    pub port: u16,
    pub endpoint: String,
    pub client_id: String,
    pub client_secret: String,
    pub jwt_pub_key: String,
    pub org_name: String,
    pub app_name: Option<String>,
    #[cfg(not(feature = "builtin-casbin"))]
    pub permission_name: String,
    #[cfg(feature = "builtin-casbin")]
    pub casdoor_db: String,
}

/// User info struct, defined in the SDK.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CasdoorUser {
    pub owner: String,
    pub name: String,
    pub created_time: String,
    pub updated_time: String,

    pub id: String,
    pub r#type: String,
    pub password: String,
    pub display_name: String,
    pub avatar: String,
    pub permanent_avatar: String,
    pub email: String,
    pub phone: String,
    pub location: String,
    pub address: Vec<String>,
    pub affiliation: String,
    pub title: String,
    pub id_card_type: String,
    pub id_card: String,
    pub homepage: String,
    pub bio: String,
    pub tag: String,
    pub region: String,
    pub language: String,
    pub score: i32,
    pub ranking: i32,

    pub is_online: bool,
    pub is_admin: bool,
    pub is_global_admin: bool,
    pub is_forbidden: bool,

    pub signup_application: String,
    pub hash: String,
    pub pre_hash: String,

    pub github: String,
    pub google: String,
    pub qq: String,
    pub wechat: String,
    pub facebook: String,
    pub dingtalk: String,
    pub weibo: String,
    pub gitee: String,
    pub linkedin: String,
    pub wecom: String,
    pub lark: String,
    pub gitlab: String,
    pub ldap: String,

    pub properties: HashMap<String, String>,
}
