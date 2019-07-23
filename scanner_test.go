package scanner

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScanner_Start(t *testing.T) {
	host, port, _ := net.SplitHostPort(testListener(t))
	scanner, err := New(host, port, nil)
	require.Nil(t, err, err)
	err = scanner.Start()
	require.Nil(t, err, err)
	for c := range scanner.Conns {
		_ = c.Close()
	}
}

func TestScanner_Stop(t *testing.T) {
	host, port, _ := net.SplitHostPort(testListener(t))
	scanner, err := New(host, port, nil)
	require.Nil(t, err, err)
	err = scanner.Start()
	require.Nil(t, err, err)
	scanner.Stop()
}

func testListener(t *testing.T) string {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				_, _ = conn.Read(make([]byte, 1024))
				_ = conn.Close()
			}(conn)
		}
	}()
	return listener.Addr().String()
}
