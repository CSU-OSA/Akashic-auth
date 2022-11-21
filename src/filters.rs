use std::collections::HashMap;
use warp::{Filter, Rejection, Reply};

use crate::handlers;

/// GET /authenticate
pub fn authenticate() -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::path!("authenticate")
        .and(warp::get())
        .and(warp::header::optional::<String>("Authorization"))
        .and(warp::header::<String>("X-Forwarded-Method"))
        .and(warp::header::<String>("X-Forwarded-Uri"))
        .and_then(handlers::handle_authenticate)
}

/// GET /login
pub fn login() -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::path!("login")
        .and(warp::get())
        .and(warp::query::<HashMap<String, String>>())
        .and_then(handlers::handle_login)
}
