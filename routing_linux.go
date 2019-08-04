package scanner

import (
	"net"

	"github.com/google/gopacket/routing"
)

type router struct {
	mac    net.HardwareAddr
	router routing.Router
}

func (r *router) route(dst net.IP) (gateway, preferredSrc net.IP, err error) {
	_, g, src, err := r.router.RouteWithSrc(r.mac, nil, dst)
	return g, src, err
}

func newRouter(iface *Interface) (*router, error) {
	r, err := routing.New()
	if err != nil {
		return nil, err
	}
	return &router{router: r, mac: iface.MAC}, nil
}
