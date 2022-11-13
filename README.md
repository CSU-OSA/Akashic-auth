# Akashic-auth

A gateway service working with Casdoor and Caddy.

一个与 [Casdoor](https://github.com/casdoor/casdoor)、[Caddy](https://github.com/caddyserver/caddy) 共同工作的网关微服务。

## 构建运行

```shell
# Release build with builtin casbin support
# You can also build a version that only using casdoor api 
to enforce permission by running
# ~$ cargo build --no-default-features
cargo build --release

cd target/release

# Run with configuration ./config.toml and ./model.conf (if using builtin casbin)
./akashic-auth

# Run with specific configuration and model (if using builtin casbin)
./akashic-auth -c <CONFIG> -m <MODEL>

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
# This name will be used to request casdoor enforce api
# Not required if builtin casbin feature has been disabled
permission_name = "permission-akashic"
# Casdoor database url (required if builtin casbin enabled)
# Service will use its table "akashic_policy" 
# to read the policies by default
# You need to modify the code in "src/actions.rs" and "sql-data.json"
# to use other table name
casdoor_db = "mysql://db_user:db_pwd@locahost:3306/db_name"
```

## 内置 Casbin

默认将启用内置 Casbin 特性进行项目编译。内置 Casbin 将使用你所指定的模型文件以及存放策略表（默认策略表名为 `akashic_policy` ）的 MySQL 数据库实施权限控制。为了利用 Casdoor 提供的前端页面进行权限修改，指定的数据库可以与 Casdoor 所使用的相同。

使用内置 Casbin 实施权限控制将获得比使用 Casdoor API 更快的请求响应速度。经粗略测试，在我们的使用场景中，仅通过切换内置 Casbin 进行鉴权使得响应时间从原来的 `500ms ~ 2s` 范围内浮动降低至 `230ms` 左右。