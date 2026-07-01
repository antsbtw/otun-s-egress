package egress

import (
	"github.com/antsbtw/otun-s-egress/node/hy2node"
	"github.com/antsbtw/otun-s-egress/node/realitynode"
	"github.com/antsbtw/otun-s-egress/node/ssnode"
	"github.com/antsbtw/otun-s-egress/node/trojannode"
	"github.com/antsbtw/otun-s-egress/node/tuicnode"
	"github.com/antsbtw/otun-s-egress/node/vmessnode"
)

// Compile-time proof that every protocol node satisfies the Node interface — so
// realm-agent can hold any of them behind one type.
var (
	_ Node = (*hy2node.Node)(nil)
	_ Node = (*tuicnode.Node)(nil)
	_ Node = (*realitynode.Node)(nil)
	_ Node = (*trojannode.Node)(nil)
	_ Node = (*ssnode.Node)(nil)
	_ Node = (*vmessnode.Node)(nil)
)
