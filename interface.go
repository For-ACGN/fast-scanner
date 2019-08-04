package scanner

import (
	"fmt"
	"net"
)

type Interface struct {
	Name     string // windows: "Ethernet0"          linux: "eth0"
	Device   string // windows: "\Device\NPF_{GUID}" linux: "eth0"
	MAC      net.HardwareAddr
	IPNets   []*net.IPNet
	Gateways []net.IP
}

// if name is "" select the first interface
func SelectInterface(name string) (*Interface, error) {
	ifaces, err := GetAllInterface()
	if err != nil {
		return nil, err
	}
	if name == "" {
		return ifaces[0], nil
	}
	for i := 0; i < len(ifaces); i++ {
		if ifaces[i].Name == name {
			return ifaces[i], nil
		}
	}
	return nil, fmt.Errorf("interface: %s doesn't exist", name)
}
