package scanner

import (
	"errors"
	"fmt"
	"net"
)

type route struct {
	ipv4Nets    []*net.IPNet
	ipv6Nets    []*net.IPNet
	ipv4Gateway map[*net.IP]struct{}
	ipv6Gateway map[*net.IP]struct{}
}

func (r *route) route(dst net.IP) (gateway, preferredSrc net.IP, err error) {
	if !(len(dst) == net.IPv4len || len(dst) == net.IPv6len) &&
		!dst.Equal(net.IPv4bcast) &&
		!dst.IsUnspecified() &&
		!dst.IsMulticast() &&
		!dst.IsLinkLocalUnicast() {
		err = errors.New("invalid ip")
		return
	}
	// check is LAN
	if dst.To4() != nil {
		if len(r.ipv4Nets) == 0 {
			err = errors.New("no ipv4 net")
			return
		}
		for _, ipnet := range r.ipv4Nets {
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
		for _, ipnet := range r.ipv6Nets {
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

func newRouter(iface *Interface) (*route, error) {
	if len(iface.IPNets) == 0 {
		return nil, errors.New("no ip")
	}
	r := &route{
		ipv4Gateway: make(map[*net.IP]struct{}),
		ipv6Gateway: make(map[*net.IP]struct{}),
	}
	for _, ipnet := range iface.IPNets {
		switch len(ipnet.Mask) {
		case net.IPv4len:
			r.ipv4Nets = append(r.ipv4Nets, ipnet)
		case net.IPv6len:
			r.ipv6Nets = append(r.ipv6Nets, ipnet)
		}
	}
	for i := 0; i < len(iface.Gateways); i++ {
		if iface.Gateways[i].To4() != nil { // ipv4
			r.ipv4Gateway[&iface.Gateways[i]] = struct{}{}
		} else { // ipv6
			r.ipv6Gateway[&iface.Gateways[i]] = struct{}{}
		}
	}
	return r, nil
}
