package scanner

import (
	"fmt"
	"log"
	"testing"

	"github.com/stretchr/testify/require"
)

func ExampleGenerator() {
	testdata := [][]string{
		{"192.168.1.1"},
		{"192.168.1.1-192.168.1.1"},
		{"192.168.1.1-192.168.1.3"},
		{"192.168.1.1/31"},
		{"fe80::1"},
		{"fe80::1-fe80::1"},
		{"fe80::1-fe80::2"},
		{"::1-::2"},
	}
	for _, targets := range testdata {
		generator, err := NewGenerator(targets)
		if err != nil {
			log.Fatalln(err)
		}
		fmt.Println("number:", generator.N)
		for ip := range generator.IP {
			fmt.Println(ip, len(ip))
		}
	}

	// check number
	l := len(testdata)
	targets := make([]string, l)
	for i := 0; i < l; i++ {
		targets[i] = testdata[i][0]
	}
	generator, err := NewGenerator(targets)
	if err != nil {
		log.Fatalln(err)
	}
	generator.Close()
	fmt.Println("number:", generator.N)

	// Output:
	// number: 1
	// 192.168.1.1 4
	// number: 1
	// 192.168.1.1 4
	// number: 3
	// 192.168.1.1 4
	// 192.168.1.2 4
	// 192.168.1.3 4
	// number: 2
	// 192.168.1.0 4
	// 192.168.1.1 4
	// number: 1
	// fe80::1 16
	// number: 1
	// fe80::1 16
	// number: 2
	// fe80::1 16
	// fe80::2 16
	// number: 2
	// ::1 16
	// ::2 16
	// number: 13
}

func TestNewGenerator(t *testing.T) {
	testdata := [][]string{
		// single
		{"192.168.1.256"}, // invalid single ipv4
		{"fg::1"},         // invalid single ipv6
		// range
		{"192.168.1.1-192.168.1.1-"},  // 2 "-"
		{"192.168.1.256-192.168.1.1"}, // invalid start ipv4
		{"fg::1-fg::1"},               // invalid start ipv6
		{"192.168.1.1-192.168.1.256"}, // invalid stop ipv4
		{"fe80::1-fg80::1"},           // invalid stop ipv6
		{"192.168.1.1-fe80::1"},       // start ip type != stop ip type
		{"fe80::1-192.168.1.1"},       // start ip type != stop ip type
		{"192.168.1.2-192.168.1.1"},   // start ipv4 > stop ipv6
		{"fe80::2-fe80::1"},           // start ipv6 > stop ipv6
		// CIDR
		{"192.168.1.1/33"}, // ipv4
		{"fe80::1/129"},    // ipv6
		// range & CIDR
		{"192.168.1.1-192.168.1.2/24"},
		// interrupt
		{"192.168.1.2-192.168.1.22", "192.168.1.256"},
		{"192.168.1.2-192.168.1.255", "192.168.1.255", "192.168.1.256"},
	}
	for _, targets := range testdata {
		_, err := NewGenerator(targets)
		require.NotNil(t, err)
	}
}
