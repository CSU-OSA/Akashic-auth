# Akashic-auth

A gateway service working with Casdoor and Caddy.

一个与 [Casdoor](https://github.com/casdoor/casdoor)、[Caddy](https://github.com/caddyserver/caddy) 共同工作的网关微服务。

## 构建运行

```shell
# Release build
cargo build --release

cd target/release

# Run with configuration ./config.toml
./akashic-auth

# Run with specific configuration
./akashic-auth -c <CONFIG>

# More help
./akashic-auth -h
```

## 配置文件

配置示例见 `config.toml.example`

```toml
# Listen address
address = "127.0.0.1"
# Listen port
port = 9000
# Casdoor Server Url, such as http://localhost:8000
endpoint = "http://localhost:8000"
# Client ID for the Casdoor application
client_id = ""
# Client secret for the Casdoor application
client_secret = ""
# The public key for the Casdoor application's cert
jwt_pub_key = ""
# The name for the Casdoor organization
org_name = "Akashic"
# Permission name in casddor web ui
permission_name = "permission-akashic"
```