package distro

import (
	"github.com/sagernet/sing-box/adapter/outbound"

	"github.com/xchacha20-poly1305/husi/libcore/v2/plugin/balancer"
	"github.com/xchacha20-poly1305/husi/libcore/v2/plugin/trusttunnel"
	"github.com/xchacha20-poly1305/husi/libcore/v2/plugin/vless"
)

func registerPluginsOutbound(registry *outbound.Registry) {
	vless.RegisterOutbound(registry)
	trusttunnel.RegisterOutbound(registry)
	balancer.RegisterOutbound(registry)
}
