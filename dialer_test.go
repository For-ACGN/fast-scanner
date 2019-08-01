package scanner

import (
	"bytes"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDialer_getLocalAddr(t *testing.T) {
	// no local ip
	dialer, err := NewDialer(nil, time.Second)
	require.NoError(t, err)
	require.Nil(t, dialer.getLocalAddrv4())
	require.Nil(t, dialer.getLocalAddrv6())
	// with local ip
	dialer, err = NewDialer([]string{"192.168.1.200", "2606::1"}, time.Second)
	require.NoError(t, err)
	expected := bytes.Buffer{}
	for i := 1024; i < 65536; i++ {
		expected.WriteString("192.168.1.200:")
		expected.WriteString(strconv.Itoa(i))
		expected.WriteString("\n")
		expected.WriteString("[2606::1]:")
		expected.WriteString(strconv.Itoa(i))
		expected.WriteString("\n")
	}
	// cycle
	expected.WriteString("192.168.1.200:1024\n")
	expected.WriteString("[2606::1]:1024\n")
	actual := &bytes.Buffer{}
	for i := 0; i < 65536-1024+1; i++ {
		_, _ = fmt.Fprintln(actual, dialer.getLocalAddrv4())
		_, _ = fmt.Fprintln(actual, dialer.getLocalAddrv6())
	}
	require.True(t, expected.String() == actual.String())
}

func TestDialer_Dial(t *testing.T) {
	// ipv4
	iface, err := selectInterface("")
	require.NoError(t, err)
	l := len(iface.IPNets)
	localIPs := make([]string, l)
	for i := 0; i < l; i++ {
		localIPs[i] = iface.IPNets[i].IP.String()
	}
	dialer, err := NewDialer(localIPs, 10*time.Second)
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
	_, err = dialer.Dial("tcp", "[2606:4700:4700::1001]:66666")
	require.Error(t, err)
	_, err = dialer.Dial("tcp", "[2606:4700:ffff::ffff]:65531")
	require.Error(t, err)
}
