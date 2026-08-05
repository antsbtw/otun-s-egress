package realm

import (
	"fmt"
	"net/netip"
)

// ParseRelayAddresses 把下发的 "ip:port" 文本解析成地址表（中继回退，
// RELAY_FALLBACK_DESIGN.md §3.2）。
//
// 🔴 解析失败即报错，不静默跳过：配错了要在启动时立刻可见。静默丢弃会退化成
// 纯打洞，在对称 NAT 客户端上表现为"配了中继但没生效"，极难排查 —— 与
// DirectAddresses 的处理口径一致（hy2node.go 那条注释记录了同一个教训）。
//
// 空输入返回 nil, nil：不配中继是合法的默认状态（不启用回退）。
func ParseRelayAddresses(addresses []string) ([]netip.AddrPort, error) {
	if len(addresses) == 0 {
		return nil, nil
	}
	out := make([]netip.AddrPort, 0, len(addresses))
	for _, s := range addresses {
		ap, err := netip.ParseAddrPort(s)
		if err != nil {
			return nil, fmt.Errorf("parse relay_addresses %q: %w", s, err)
		}
		out = append(out, ap)
	}
	return out, nil
}
