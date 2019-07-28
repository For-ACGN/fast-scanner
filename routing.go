package scanner

import (
	"net"

	"github.com/google/gopacket/routing"
)

type route struct {
}

func (r *route) Route(dst net.IP) (
	iface *net.Interface, gateway, preferredSrc net.IP, err error) {

}

func (r *route) RouteWithSrc(input net.HardwareAddr, src, dst net.IP) (
	iface *net.Interface, gateway, preferredSrc net.IP, err error) {

}

func newRouter() (routing.Router, error) {

}
