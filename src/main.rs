mod entity;
mod filters;
mod handlers;
mod response;

#[cfg(feature = "builtin-casbin")]
mod actions;
#[cfg(feature = "builtin-casbin")]
mod adapter;
#[cfg(feature = "builtin-casbin")]
mod error;

#[cfg(feature = "builtin-casbin")]
use adapter::SqlxAdapter;
#[cfg(feature = "builtin-casbin")]
use casbin::DefaultModel;
#[cfg(feature = "builtin-casbin")]
use once_cell::sync::OnceCell;

use chrono::Local;
use clap::Parser;
use entity::Config;
use lazy_static::lazy_static;
use log::info;
use pretty_env_logger::env_logger;
use reqwest::Client;
use std::{io::Write, net::SocketAddr};
use warp::Filter;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Configuration's absolute path
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    #[cfg(feature = "builtin-casbin")]
    /// Permission model file's absolute path
    #[arg(short, long, default_value = "model.conf")]
    model: String,
}

#[cfg(feature = "builtin-casbin")]
static MODEL: OnceCell<DefaultModel> = OnceCell::new();
#[cfg(feature = "builtin-casbin")]
static ADAPTER: OnceCell<SqlxAdapter> = OnceCell::new();

lazy_static! {
    static ref CONFIG: Config = load_conf();
    static ref ARGS: Args = Args::parse();
    static ref CLIENT: Client = Client::new();
}

/// initialize logger
fn init_log() {
    let env = env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info");
    env_logger::Builder::from_env(env)
        .format(|buf, record| {
            let level = { buf.default_styled_level(record.level()) };
            writeln!(
                buf,
                "{} {} [{}] {}",
                Local::now().format("%Y-%m-%d %H:%M:%S"),
                format_args!("{:>5}", level),
                record.module_path().unwrap_or("<unnamed>"),
                &record.args()
            )
        })
        .init();
}

/// load configuration
fn load_conf() -> Config {
    config::Config::builder()
        .add_source(config::File::with_name(&ARGS.config))
        .build()
        .unwrap()
        .try_deserialize::<Config>()
        .map(|c| Config {
            jwt_pub_key: c.jwt_pub_key.replace("CERTIFICATE", "PUBLIC KEY"),
            ..c
        })
        .unwrap()
}

/// load permission model and policy adapter
#[cfg(feature = "builtin-casbin")]
async fn load_perm() {
    let model = DefaultModel::from_file(&ARGS.model).await.unwrap();
    if let Err(_) = MODEL.set(model) {
        panic!("Load permission model into memory failed")
    }
    let adapter = SqlxAdapter::new(&CONFIG.casdoor_db, 8).await.unwrap();
    if let Err(_) = ADAPTER.set(adapter) {
        panic!("Load permission adapter into memory failed")
    }
}

#[tokio::main]
async fn main() {
    init_log();

    #[cfg(feature = "builtin-casbin")]
    load_perm().await;

    let log = warp::log::custom(|info| {
        info!("{} {}, {}", info.method(), info.path(), info.status());
    });

    let route = filters::authenticate()
        .or(filters::login())
        .recover(handlers::err_handle)
        .with(log);

    let addr = SocketAddr::new(
        CONFIG.address.parse().expect("Parse address failed"),
        CONFIG.port,
    );
    warp::serve(route).run(addr).await;
}
