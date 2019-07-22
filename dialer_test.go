package scanner

import (
	"bytes"
	"fmt"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetLocalAddr(t *testing.T) {
	// no local address
	scanner, err := New("192.168.1.1", "1080", nil)
	require.Nil(t, err, err)
	require.Nil(t, scanner.getLocalAddr())
	// with local address
	expected := bytes.Buffer{}
	for i := 1024; i < 65536; i++ {
		expected.WriteString("192.168.1.200:")
		expected.WriteString(strconv.Itoa(i))
		expected.WriteString("\n")
		expected.WriteString("192.168.1.201:")
		expected.WriteString(strconv.Itoa(i))
		expected.WriteString("\n")
	}
	expected.WriteString("192.168.1.200:1024\n")
	expected.WriteString("192.168.1.201:1024\n")
	opt := &Options{LocalAddrs: "192.168.1.200,192.168.1.201"}
	scanner, err = New("192.168.1.1", "1080", opt)
	require.Nil(t, err, err)
	actual := &bytes.Buffer{}
	for i := 0; i < 2*(65536-1024)+2; i++ {
		_, _ = fmt.Fprintln(actual, scanner.getLocalAddr())
	}
	require.Equal(t, expected.String(), actual.String())
}
