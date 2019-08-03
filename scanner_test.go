package scanner

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScanner_Start(t *testing.T) {
	for addr := range testnewScanner(t).Result {
		t.Log(addr)
	}
}

func TestScanner_Stop(t *testing.T) {
	testnewScanner(t).Stop()
}

func testnewScanner(t *testing.T) *Scanner {
	_, port, _ := net.SplitHostPort(testListener(t))
	iface, err := SelectInterface("")
	require.NoError(t, err)
	host := iface.IPNets[0].IP.String()
	s, err := New(host, port, &Options{Method: MethodConnect})
	require.NoError(t, err)
	err = s.Start()
	require.NoError(t, err)
	return s
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
				_ = conn.Close()
			}(conn)
		}
	}()
	return listener.Addr().String()
}
