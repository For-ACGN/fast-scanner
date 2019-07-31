package scanner

import (
	"fmt"
	"net"
	"strconv"

	"github.com/StackExchange/wmi"
)

func selectInterface(name string) (*Interface, error) {
	type Win32NetworkAdapter struct {
		NetConnectionID string
		GUID            string // GUID=SettingID
	}
	var adapters []Win32NetworkAdapter
	q := "SELECT * FROM Win32_NetworkAdapter WHERE NetEnabled = TRUE"
	err := wmi.Query(q, &adapters)
	if err != nil {
		return nil, err
	}
	type Win32NetworkAdapterConfiguration struct {
		SettingID        string
		MACAddress       string
		IPAddress        []string
		IPSubnet         []string
		DefaultIPGateway []string
	}
	var configs []Win32NetworkAdapterConfiguration
	q = "SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE"
	err = wmi.Query(q, &configs)
	if err != nil {
		return nil, err
	}
	ifaces := make(map[string]*Interface)
	for _, adapter := range adapters {
		iface := &Interface{
			Device: "\\Device\\NPF_" + adapter.GUID,
		}
		ifaces[adapter.NetConnectionID] = iface
		for _, config := range configs {
			if config.SettingID == adapter.GUID {
				// set MAC Address
				iface.MAC, _ = net.ParseMAC(config.MACAddress)
				// set IP Nets
				l := len(config.IPAddress)
				iface.IPNets = make([]*net.IPNet, l)
				for i := 0; i < l; i++ {
					ip := net.ParseIP(config.IPAddress[i])
					var mask net.IPMask
					if ip.To4() != nil { // ipv4
						mask = net.IPMask(net.ParseIP(config.IPSubnet[i]).To4())
					} else { // ipv6
						n, _ := strconv.Atoi(config.IPSubnet[i])
						mask = net.CIDRMask(n, 128)
					}
					iface.IPNets[i] = &net.IPNet{
						IP:   ip,
						Mask: mask,
					}
				}
				l = len(config.DefaultIPGateway)
				iface.Gateways = make([]net.IP, l)
				for i := 0; i < l; i++ {
					iface.Gateways[i] = net.ParseIP(config.DefaultIPGateway[i])
				}
			}
		}
	}
	i := ifaces[name]
	if i == nil {
		return nil, fmt.Errorf("interface: %s doesn't exist", name)
	}
	return i, nil
}
