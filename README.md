# Banner 指纹识别

接收一批网络扫描原始数据（`ip`、`port`、`banner`），识别协议、软件、版本和操作系统线索。服务不主动探测目标。

示例数据只用于自测。评估时会换一批没有出现在本仓库里的 banner，认不出来应返回 `unknown`，不能因此让进程退出或整批失败。

## 做什么

- **server**：常驻进程。`POST /fingerprint` 批量识别，`GET /health` 报告进程和规则是否就绪。
- **client**：独立命令。读取本地 JSON 文件，发给 server，把结果打到标准输出。
- 规则写在 [`rules/fingerprints.json`](rules/fingerprints.json)。引擎只按优先级做正则抽取，产品名和置信度不写死在 Go 代码里。

一条结果固定为这些字段：

| 字段 | 含义 |
| --- | --- |
| `ip` / `port` | 原样带回，顺序与输入一致 |
| `protocol` | 如 `SSH`、`HTTP`、`MySQL`、`Redis`、`FTP`。认不出为 `unknown` |
| `product` | 软件名，如 `OpenSSH`、`nginx`、`Apache`、`Jetty` |
| `version` | 能抽到的版本，没有则为空字符串 |
| `os_hint` | banner 里能看出的系统线索，没有则为空字符串 |
| `confidence` | 0 到 1。该值写在命中的那条规则上 |

自测样例的前 7 条对应下面这种深度（完整输入在 [`testdata/sample.json`](testdata/sample.json)）：

```json
[
  {"ip":"1.2.3.4","port":22,"protocol":"SSH","product":"OpenSSH","version":"8.9p1","os_hint":"Ubuntu","confidence":0.95},
  {"ip":"1.2.3.5","port":80,"protocol":"HTTP","product":"nginx","version":"1.24.0","os_hint":"","confidence":0.9},
  {"ip":"1.2.3.6","port":443,"protocol":"HTTP","product":"Apache","version":"2.4.57","os_hint":"","confidence":0.9},
  {"ip":"1.2.3.7","port":3306,"protocol":"MySQL","product":"MySQL","version":"8.0.32","os_hint":"","confidence":0.9},
  {"ip":"1.2.3.8","port":6379,"protocol":"Redis","product":"Redis","version":"","os_hint":"","confidence":0.7},
  {"ip":"1.2.3.9","port":21,"protocol":"FTP","product":"ProFTPD","version":"1.3.7","os_hint":"","confidence":0.9},
  {"ip":"1.2.3.10","port":8080,"protocol":"HTTP","product":"Jetty","version":"9.4.51","os_hint":"","confidence":0.85}
]
```

`SSH-2.0-OpenSSH_8.9p1 Ubuntu-3` 会拆成协议、产品、版本 `8.9p1` 和系统线索 `Ubuntu`。只有 `+PONG` 或 Redis 错误文本时，协议和产品仍然是 Redis，版本留空，置信度低于带版本的命中。`QUIT` 这种对不上任何规则的内容返回 `unknown`。

## 启动

在仓库根目录执行：

```bash
docker compose up --build
```

server 通过健康检查后，client 才会读取 `/data/sample.json` 并打印结果。client 退出码为 0 后，server 继续运行。看完日志可以 `Ctrl+C`，或在另一个终端执行 `docker compose stop`。

只看识别结果、不把 server 日志混在一起：

```bash
docker compose up -d --build
docker compose run --rm client
```

用自己的验收文件（内容仍是 JSON 数组）：

```bash
docker compose up -d --build
docker compose run --rm -v /绝对路径/accept.json:/data/accept.json:ro -e FINGERPRINT_INPUT=/data/accept.json client
```

Windows PowerShell 把 `/绝对路径/accept.json` 换成本机路径即可。`testdata` 目录已经挂到容器的 `/data`，也可以直接替换 [`testdata/sample.json`](testdata/sample.json) 后再执行 `docker compose run --rm client`。

## 接口

`POST /fingerprint`

请求体是数组：

```json
[
  {"ip": "1.2.3.4", "port": 22, "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"}
]
```

响应是等长数组。某一条字段类型不对，这一条变成 `unknown`，其余照常返回。整个请求体不是 JSON 数组时返回 400。空 banner、无法识别的 banner 都返回 200，协议为 `unknown`。

`GET /health`

规则已加载：

```json
{"status":"ok","rules_loaded":39}
```

`rules_loaded` 是当前启用的规则条数，规则文件增减后这个数字会变。规则没加载好时返回 503。容器健康检查执行的是镜像里的 `/server healthcheck`，它会访问这个接口，而不是只看端口有没有打开。

## 规则怎么加

编辑 `rules/fingerprints.json`，增加一条对象后重新构建 server 镜像。不需要改 Go 代码。

```json
{
  "id": "acme",
  "description": "一句话说明这条规则在认什么",
  "priority": 100,
  "pattern": "Acme/([0-9.]+)",
  "protocol": "HTTP",
  "product": "Acme",
  "version_group": 1,
  "confidence": 0.9
}
```

- `priority` 越大越先匹配。更具体的规则（带版本、带系统）放在更高优先级。
- `pattern` 是 RE2 正则。版本、系统、产品名用捕获组抽出，再用 `version_group`、`os_hint_group`、`product_group` 指定第几组。组号从 1 开始。
- `product` 写死时优先使用字面量，例如示例要求 Apache 的产品名是 `Apache`。
- `os_hint` 可以写死；若捕获到的文本在 `os_aliases` 里（不区分大小写），会换成规范写法，例如 `win64` 变成 `Windows`。
- `confidence` 必须在 0 到 1 之间。认不出时引擎自己填 0，不需要写一条 unknown 规则。
- `"enabled": false` 可以停用一条规则。
- 正则编译失败或文件里没有可用规则时，server 启动失败，健康检查不会变绿。

端口不参与判断。80 端口上的非 HTTP banner 不会因为端口号被当成 HTTP。

扫描器有时把二进制 banner 写成字面量 `\r`、`\n`、`\xNN`、`\u0000`。引擎在匹配前会还原这些转义；JSON 里已经解码成真实字节的 banner 保持原样。

## 部署上的取舍

这个系统的调用方就是旁边那个一次性 client，没有第二个需要从宿主机直连的人。所以 compose 把两个容器放进 `internal: true` 的网络，client 访问 `http://server:8080`，compose 文件里没有 `ports`。

client 使用 `depends_on.condition: service_healthy`。健康检查命令是容器内的静态二进制去请求 `GET /health`，`/health` 在 `rules_loaded` 为 0 时返回 503。这样避开的是「端口已经打开但规则还没装进内存」这种假就绪。

镜像分成编译阶段和运行阶段。编译阶段用 Go 工具链做出 `CGO_ENABLED=0` 的静态二进制；运行阶段是 `scratch`，里面只有二进制、规则文件和一份 passwd。运行用户是 `65532`，再去掉全部 capabilities，加上 `no-new-privileges` 和只读根文件系统。镜像里没有 shell，`docker exec` 进不去是预期结果。

规则文件在构建时复制到 `/rules/fingerprints.json`，由 `RULES_PATH` 指给进程。换一份规则是换数据文件，不是改匹配引擎。

## 本地开发

本机需要 Go 1.22 或更高版本。在仓库根目录：

```bash
go test ./...
go run ./cmd/server
go run ./cmd/client -input testdata/sample.json -server http://127.0.0.1:8080
```

client 把 JSON 打到标准输出，把「共几条、未知几条」打到标准错误。结果里含有 `unknown` 时退出码仍是 0。文件读不到、服务连不上或服务返回 4xx/5xx 时退出码是 2。
