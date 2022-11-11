mod entity;
mod filters;
mod handlers;
mod response;

use chrono::Local;
use clap::Parser;
use entity::Config;
use lazy_static::lazy_static;
use log::info;
use pretty_env_logger::env_logger;
use std::{io::Write, net::SocketAddr};
use warp::Filter;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Configuration absolute path
    #[arg(short, long, default_value = "config.toml")]
    config: String,
}

lazy_static! {
    static ref CONFIG: Config = load_conf();
    static ref ARGS: Args = Args::parse();
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

#[tokio::main]
async fn main() {
    init_log();

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
