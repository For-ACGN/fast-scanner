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
	dialer, err = NewDialer("192.168.1.200", time.Second)
	require.Nil(t, err, err)
	expected := bytes.Buffer{}
	for i := 1024; i < 65536; i++ {
		expected.WriteString("192.168.1.200:")
		expected.WriteString(strconv.Itoa(i))
		expected.WriteString("\n")
	}
	// cycle
	expected.WriteString("192.168.1.200:1024\n")
	actual := &bytes.Buffer{}
	for i := 0; i < 65536-1024+1; i++ {
		_, _ = fmt.Fprintln(actual, dialer.getLocalAddr())
	}
	require.True(t, expected.String() == actual.String())
}
