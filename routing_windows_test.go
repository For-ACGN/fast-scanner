package scanner

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRoute(t *testing.T) {
	iface, err := selectInterfaces("Ethernet0")
	require.Nil(t, err)
	route, err := newRouter(iface)
	require.Nil(t, err)
	// ipv4
	g, src, err := route.route(net.ParseIP("192.168.1.1"))
	require.Nil(t, err)
	require.Nil(t, g)
	t.Log("src:", src)
	g, src, err = route.route(net.ParseIP("1.1.1.1"))
	require.Nil(t, err)
	t.Log("gateway:", g, "src:", src)
	// ipv6
	g, src, err = route.route(net.ParseIP("fe80::1"))
	require.Nil(t, err)
	require.Nil(t, g)
	t.Log("src:", src)
	g, src, err = route.route(net.ParseIP("240c::1"))
	require.Nil(t, err)
	t.Log("gateway:", g, "src:", src)
}
