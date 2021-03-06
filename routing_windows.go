package scanner

import (
	"errors"
	"fmt"
	"net"
)

type router struct {
	ipv4Nets    []*net.IPNet
	ipv6Nets    []*net.IPNet
	ipv4Gateway map[*net.IP]struct{}
	ipv6Gateway map[*net.IP]struct{}
}

func (r *router) route(dst net.IP) (gateway, preferredSrc net.IP, err error) {
	if !((len(dst) == net.IPv4len || len(dst) == net.IPv6len) &&
		!dst.Equal(net.IPv4bcast) &&
		!dst.IsUnspecified() &&
		!dst.IsMulticast() &&
		!dst.IsLoopback()) {
		err = errors.New("invalid ip")
		return
	}
	if dst.To4() != nil {
		if len(r.ipv4Nets) == 0 {
			err = errors.New("no ipv4 net")
			return
		}
		// check is LAN
		for _, ipnet := range r.ipv4Nets {
			if ipnet.IP.Equal(dst) {
				err = errRouteSelf
				return
			}
			if ipnet.Contains(dst) {
				preferredSrc = ipnet.IP
				return
			}
		}
		// intranet
		for g := range r.ipv4Gateway {
			preferredSrc = r.ipv4Nets[0].IP
			gateway = *g
			return
		}
	} else if dst.To16() != nil {
		if len(r.ipv6Nets) == 0 {
			err = errors.New("no ipv6 net")
			return
		}
		// check is LAN
		for _, ipnet := range r.ipv6Nets {
			if ipnet.IP.Equal(dst) {
				err = errRouteSelf
				return
			}
			if ipnet.Contains(dst) {
				preferredSrc = ipnet.IP
				return
			}
		}
		// intranet
		for g := range r.ipv6Gateway {
			for _, ipnet := range r.ipv6Nets {
				if ipnet.IP.IsGlobalUnicast() {
					preferredSrc = ipnet.IP
					gateway = *g
					return
				}
			}
		}
	} else {
		err = fmt.Errorf("invalid ip: %s", dst)
		return
	}
	return nil, nil, errors.New("no gateway")
}

func newRouter(iface *Interface) (*router, error) {
	if len(iface.IPNets) == 0 {
		return nil, errors.New("no ip")
	}
	r := &router{
		ipv4Gateway: make(map[*net.IP]struct{}),
		ipv6Gateway: make(map[*net.IP]struct{}),
	}
	for _, ipnet := range iface.IPNets {
		switch len(ipnet.Mask) {
		case net.IPv4len:
			ipnet.IP = ipnet.IP.To4()
			r.ipv4Nets = append(r.ipv4Nets, ipnet)
		case net.IPv6len:
			ipnet.IP = ipnet.IP.To16()
			r.ipv6Nets = append(r.ipv6Nets, ipnet)
		}
	}
	for i := 0; i < len(iface.Gateways); i++ {
		g := iface.Gateways[i].To4()
		if g != nil { // ipv4
			r.ipv4Gateway[&g] = struct{}{}
		} else { // ipv6
			g := iface.Gateways[i].To16()
			r.ipv6Gateway[&g] = struct{}{}
		}
	}
	return r, nil
}
