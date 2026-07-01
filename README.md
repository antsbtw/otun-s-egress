# otun-s-egress

OTun over-realm **出口（egress）节点**，独立于会合面（rendezvous）单独管理与迭代。

一个统一二进制 `otun-egress` 按配置的 `protocol` 字段运行六种 over-realm 协议中的任意一种，
把经打洞（或未来的公网直连回退）到达的流量出口到公网。协议引擎全部复用 sing / sing-quic
库（零 fork），本仓只提供「打洞 → 喂给协议引擎 → 出口」的接入胶水。

## 与会合面的关系（本仓的独立性）

- 本仓**只含出口侧代码**：`node/`、`overlay/`、`underlay/`、`transport/realm`。
- **不含会合面代码**（`core`/`wire`）。egress 生产代码对会合面零依赖；出口靠 realm 线缆协议
  （HTTP）与会合面通信，两侧独立演进。
- 会合面（撮合、打洞协调）在 `otun-s` 仓，是权威实现。需要端到端集成测试时，本仓的节点指向
  真实运行的会合面。

## 六协议

| 协议 | node 包 | 说明 |
|---|---|---|
| Hysteria2 | `node/hy2node` | sing-quic hysteria2.Service，内置 realm |
| TUIC | `node/tuicnode` | sing-quic tuic.Service |
| Reality (VLESS) | `node/realitynode` | 借壳 TLS，需 `-tags with_utls` |
| Trojan | `node/trojannode` | 经 WrapStream 可靠流 |
| Shadowsocks | `node/ssnode` | 同上，method 两端须同库 |
| VMess | `node/vmessnode` | 同上 |

## 构建

Reality 依赖 uTLS，构建带 `with_utls` tag：

```bash
# 统一二进制（推荐，一个二进制跑全部 6 协议）
go build -tags with_utls -o otun-egress ./cmd/otun-egress
# 交叉编译到 Debian/amd64 节点
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -tags with_utls -o otun-egress-linux-amd64 ./cmd/otun-egress
```

单协议二进制（`cmd/otun-hy2-node` 等）保留作兼容/调试用途。

## 部署

见 `deploy/egress/`：systemd 模板 `otun-egress@.service`（一个 realm 槽一个 instance，
`Restart=always`，非特权用户）+ `install.sh`（幂等安装）+ 示例配置（含单会合面与多会合面
failover 两种）。

## 测试

```bash
go test -tags with_utls ./...
```

本仓只含**单元测试**（参数校验等）。完整的端到端打洞测试（客户端 ↔ 真实会合面 ↔ 出口）在
`otun-s` 仓，因为它需要会合面 `core`/`wire` 起一个 rendezvous——本仓按设计不含会合面代码。
