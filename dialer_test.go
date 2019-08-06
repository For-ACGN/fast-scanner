package scanner

import (
	"bytes"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAddrPool(t *testing.T) {
	// ipv4 GlobalUnicast
	dialer, err := NewDialer([]string{"192.168.1.1-192.168.1.2"}, time.Second)
	require.NoError(t, err)
	expected := bytes.Buffer{}
	for i := 1024; i < 65536; i++ {
		expected.WriteString("192.168.1.1:")
		expected.WriteString(strconv.Itoa(i))
		expected.WriteString("\n")
		expected.WriteString("192.168.1.2:")
		expected.WriteString(strconv.Itoa(i))
		expected.WriteString("\n")
	}
	// cycle
	expected.WriteString("192.168.1.1:1024\n")
	expected.WriteString("192.168.1.2:1024\n")
	actual := bytes.Buffer{}
	for i := 0; i < 2*(65536-1024+1); i++ {
		actual.WriteString(dialer.ipv4GU.get().String() + "\n")
	}
	require.True(t, expected.String() == actual.String())
	// ipv4 LinkLocalUnicast
	dialer, err = NewDialer([]string{"169.254.1.1-169.254.1.2"}, time.Second)
	require.NoError(t, err)
	expected.Reset()
	for i := 1024; i < 65536; i++ {
		expected.WriteString("169.254.1.1:")
		expected.WriteString(strconv.Itoa(i))
		expected.WriteString("\n")
		expected.WriteString("169.254.1.2:")
		expected.WriteString(strconv.Itoa(i))
		expected.WriteString("\n")
	}
	// cycle
	expected.WriteString("169.254.1.1:1024\n")
	expected.WriteString("169.254.1.2:1024\n")
	actual.Reset()
	for i := 0; i < 2*(65536-1024+1); i++ {
		actual.WriteString(dialer.ipv4LLU.get().String() + "\n")
	}
	require.True(t, expected.String() == actual.String())
	// ipv6 GlobalUnicast
	dialer, err = NewDialer([]string{"240c::1-240c::2"}, time.Second)
	require.NoError(t, err)
	expected.Reset()
	for i := 1024; i < 65536; i++ {
		expected.WriteString("[240c::1]:")
		expected.WriteString(strconv.Itoa(i))
		expected.WriteString("\n")
		expected.WriteString("[240c::2]:")
		expected.WriteString(strconv.Itoa(i))
		expected.WriteString("\n")
	}
	// cycle
	expected.WriteString("[240c::1]:1024\n")
	expected.WriteString("[240c::2]:1024\n")
	actual.Reset()
	for i := 0; i < 2*(65536-1024+1); i++ {
		actual.WriteString(dialer.ipv6GU.get().String() + "\n")
	}
	require.True(t, expected.String() == actual.String())
	// ipv6 LinkLocalUnicast
	dialer, err = NewDialer([]string{"fe80::1-fe80::2"}, time.Second)
	require.NoError(t, err)
	expected.Reset()
	for i := 1024; i < 65536; i++ {
		expected.WriteString("[fe80::1]:")
		expected.WriteString(strconv.Itoa(i))
		expected.WriteString("\n")
		expected.WriteString("[fe80::2]:")
		expected.WriteString(strconv.Itoa(i))
		expected.WriteString("\n")
	}
	// cycle
	expected.WriteString("[fe80::1]:1024\n")
	expected.WriteString("[fe80::2]:1024\n")
	actual.Reset()
	for i := 0; i < 2*(65536-1024+1); i++ {
		actual.WriteString(dialer.ipv6LLU.get().String() + "\n")
	}
	require.True(t, expected.String() == actual.String())
}

func TestDialer_Dial(t *testing.T) {
	iface, err := SelectInterface("")
	require.NoError(t, err)
	l := len(iface.IPNets)
	localIPs := make([]string, l)
	for i := 0; i < l; i++ {
		localIPs[i] = iface.IPNets[i].IP.String()
	}
	dialer, err := NewDialer(localIPs, 5*time.Second)
	require.NoError(t, err)
	listener, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	// ipv4
	_, err = dialer.Dial("tcp", "8.8.8.8:53")
	require.NoError(t, err)
	_, err = dialer.Dial("tcp", "8.8.4.4:53")
	require.NoError(t, err)
	_, err = dialer.Dial("tcp", "127.0.0.1:"+port)
	require.NoError(t, err)
	_, err = dialer.Dial("tcp", "169.254.1.1:66666")
	require.Error(t, err)
	_, err = dialer.Dial("tcp", "169.254.1.1:53")
	require.Error(t, err)
	// ipv6
	_, err = dialer.Dial("tcp", "[2606:4700:4700::1111]:53")
	require.NoError(t, err)
	_, err = dialer.Dial("tcp", "[2606:4700:4700::1001]:53")
	require.NoError(t, err)
	_, err = dialer.Dial("tcp", "[::1]:"+port)
	require.NoError(t, err)
	_, err = dialer.Dial("tcp", "[fe80::1]:66666")
	require.Error(t, err)
	_, err = dialer.Dial("tcp", "[fe80::1]:53")
	require.Error(t, err)
}
