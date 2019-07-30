package scanner

import (
	"net"
)

type route struct {
	iface *Interface
}

func (r *route) route(dst net.IP) (
	iface *net.Interface, gateway, preferredSrc net.IP, err error) {

}

func newRouter(iface *Interface) (*route, error) {

}
