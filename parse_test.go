package Scanner

import (
	"bytes"
	"context"
	"fmt"
	"math/big"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func ExampleParseTarget() {
	testdata := []string{
		"192.168.1.1",
		"192.168.1.1,192.168.1.2",
		"192.168.1.1, 192.168.1.2",
	}
	for _, str := range testdata {
		fmt.Println(ParseTarget(str))
	}
	// Output:
	// [192.168.1.1]
	// [192.168.1.1 192.168.1.2]
	// [192.168.1.1 192.168.1.2]
}

func TestGenIPWithHyphen(t *testing.T) {
	expected := `0.0.0.1
0.0.0.1
0.0.0.2
0.0.0.3
0.0.0.4
0.0.0.5
0.0.0.6
0.0.0.7
0.0.0.8
0.0.0.9
0.0.0.10
::1
::1
::2
::3
::4
::5
::6
::7
::8
::9
::a
::b
::c
::d
::e
::f
::10
fe80::1
fe80::2
fe80::3
fe80::4
fe80::5
fe80::6
fe80::7
fe80::8
fe80::9
fe80::a
fe80::b
fe80::c
fe80::d
fe80::e
fe80::f
fe80::10
`
	ipChan := make(chan net.IP, 1)
	ctx := context.Background()
	go func() {
		genIPWithHyphen(ctx, ipChan, "0.0.0.1-0.0.0.1")
		genIPWithHyphen(ctx, ipChan, "0.0.0.1-0.0.0.10")
		genIPWithHyphen(ctx, ipChan, "::1-::1")
		genIPWithHyphen(ctx, ipChan, "::1-::10")
		genIPWithHyphen(ctx, ipChan, "fe80::1-fe80::10")
		close(ipChan)
	}()
	b := &bytes.Buffer{}
	for ip := range ipChan {
		_, _ = fmt.Fprintln(b, ip)
	}
	require.Equal(t, expected, b.String())
}

func TestGenIPWithDash(t *testing.T) {
	ip, ipnet, err := net.ParseCIDR("192.168.1.200/0")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(ip, ipnet.Mask, ipnet.IP, ipnet.Network())

	new(big.Int).SetBytes(net.IPv6unspecified)

	// 2 ^ n
	// x := new(big.Int).Lsh(big.NewInt(1), 2)

	// fmt.Println(x)
}
