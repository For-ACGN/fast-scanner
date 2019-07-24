package scanner

import (
	"bytes"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDialer_getLocalAddr(t *testing.T) {
	// no local ip
	dialer, err := NewDialer("", time.Second)
	require.Nil(t, err, err)
	require.Nil(t, dialer.getLocalAddr())
	// with local ip
	localIPs := "192.168.1.200-192.168.1.201,fe80::1-fe80::2"
	dialer, err = NewDialer(localIPs, time.Second)
	require.Nil(t, err, err)
	expected := bytes.Buffer{}
	for i := 1024; i < 65536; i++ {
		port := strconv.Itoa(i)
		expected.WriteString("192.168.1.200:")
		expected.WriteString(port)
		expected.WriteString("\n")
		expected.WriteString("192.168.1.201:")
		expected.WriteString(port)
		expected.WriteString("\n")
		expected.WriteString("[fe80::1]:")
		expected.WriteString(port)
		expected.WriteString("\n")
		expected.WriteString("[fe80::2]:")
		expected.WriteString(port)
		expected.WriteString("\n")
	}
	// cycle
	expected.WriteString("192.168.1.200:1024\n")
	expected.WriteString("192.168.1.201:1024\n")
	expected.WriteString("[fe80::1]:1024\n")
	expected.WriteString("[fe80::2]:1024\n")
	actual := &bytes.Buffer{}
	for i := 0; i < 4*(65536-1024)+4; i++ {
		_, _ = fmt.Fprintln(actual, dialer.getLocalAddr())
	}
	require.Equal(t, expected.String(), actual.String())
}
