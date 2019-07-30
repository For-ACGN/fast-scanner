package scanner

import (
	"net"
)

type Interface struct {
	Device   string
	MAC      net.HardwareAddr
	IPNets   []*net.IPNet
	Gateways []net.IP
}
