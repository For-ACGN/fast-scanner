package scanner

import (
	"net"
)

type Interface struct {
	Name     string // windows: "Ethernet0"          linux: "eth0"
	Device   string // windows: "\Device\NPF_{GUID}" linux: "eth0"
	MAC      net.HardwareAddr
	IPNets   []*net.IPNet
	Gateways []net.IP
}
