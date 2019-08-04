package scanner

import (
	"net"

	"github.com/google/gopacket/pcap"
)

func GetAllInterface() ([]*Interface, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}
	// to get MAC
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	ifsLen := len(ifs)
	l := len(devs)
	ifaces := make([]*Interface, l)
	for i := 0; i < l; i++ {
		iface := Interface{
			Name:   devs[i].Name, // same
			Device: devs[i].Name, // same
			// not need gateways
		}
		// set IPNets
		iface.IPNets = make([]*net.IPNet, len(devs[i].Addresses))
		for i, address := range devs[i].Addresses {
			iface.IPNets[i] = &net.IPNet{
				IP:   address.IP,
				Mask: address.Netmask,
			}
		}
		// set MACS
		for i := 0; i < ifsLen; i++ {
			if ifs[i].Name == iface.Name {
				iface.MAC = ifs[i].HardwareAddr
			}
		}
		ifaces[i] = &iface
	}
	return ifaces, nil
}
