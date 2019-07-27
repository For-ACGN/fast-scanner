package scanner

import (
	"context"
	"fmt"
	"log"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestSyn(t *testing.T) {
	time.Sleep(5 * time.Second)
	runtime.GOMAXPROCS(16)

	laddr, _ := net.ResolveIPAddr("ip", "192.168.1.10")

	tcpHeader := TCPHeader{
		Source:      17663,
		Destination: 3306,
		SeqNumber:   2,
		AckNumber:   0,
		Length:      5,
		Reserved:    0,
		NCE:         0,
		CTRL:        2,
		WindowSize:  0xaaaa,
		Checksum:    0,
		Urgent:      99,
	}
	data := tcpHeader.Marshal()
	data = append(data, []byte("xxx")...)

	raddr, _ := net.ResolveIPAddr("ip", "192.168.1.62")

	wgg := sync.WaitGroup{}

	ssss := func() {
		conn, err := net.ListenIP("ip4:tcp", laddr)
		if err != nil {
			log.Fatalln(err)
		}
		for i := 0; i < 10000; i++ {
			_, err := conn.WriteTo(data, raddr)
			if err != nil {
				log.Fatalln(err)
			}
		}
		wgg.Done()
	}

	start := time.Now()

	for i := 0; i < 8; i++ {
		wgg.Add(1)
		go ssss()

	}

	wgg.Wait()

	fmt.Println(time.Since(start).Seconds())

	select {}
	return

	// laddr, _ = net.ResolveIPAddr("ip", "192.168.1.200")
	conn1, err := net.ListenIP("ip4:tcp", nil)
	if err != nil {
		log.Fatalln(err)
	}

	ips, err := GenIP(context.Background(), []string{"123.206.0.1-123.206.1.254"})
	if err != nil {
		log.Fatalln(err)
	}

	wg := sync.WaitGroup{}

	send := func() {
		runtime.LockOSThread()
		for ip := range ips {
			raddr, _ := net.ResolveIPAddr("ip", ip.String())
			_, err := conn1.WriteTo(data, raddr)
			if err != nil {
				log.Fatalln(err)
			}
		}
		wg.Done()
	}

	send2 := func() {
		wg.Done()
		return
		runtime.LockOSThread()
		for ip := range ips {
			raddr, _ := net.ResolveIPAddr("ip", ip.String())
			_, err := conn1.WriteTo(data, raddr)
			if err != nil {
				log.Fatalln(err)
			}
		}

	}

	start = time.Now()

	wg.Add(2)
	go send()
	go send2()

	wg.Wait()

	fmt.Println(time.Since(start).Seconds())
	/*

		for i := 0; i < 10000; i++ {
			conn, err := net.DialIP("ip:tcp", laddr, raddr)
			if err != nil {
				fmt.Println(err)
			}

			go func(conn net.Conn) {
				conn.Read(make([]byte, 1024))
			}(conn)

		}


	*/
	select {}
}

func to4byte(str string) [4]byte {
	ip := net.ParseIP(str).To4()
	return [4]byte{ip[0], ip[1], ip[2], ip[3]}
}

// Csum TCP Checksum
func Csum(data []byte, srcip, dstip [4]byte) uint16 {

	pseudoHeader := []byte{
		srcip[0], srcip[1], srcip[2], srcip[3],
		dstip[0], dstip[1], dstip[2], dstip[3],
		0,                  // zero
		6,                  // protocol number (6 == TCP)
		0, byte(len(data)), // TCP length (16 bits), not inc pseudo header
	}

	sumThis := make([]byte, 0, len(pseudoHeader)+len(data))
	sumThis = append(sumThis, pseudoHeader...)
	sumThis = append(sumThis, data...)
	// fmt.Printf("% x\n", sumThis)

	lenSumThis := len(sumThis)
	var nextWord uint16
	var sum uint32
	for i := 0; i+1 < lenSumThis; i += 2 {
		nextWord = uint16(sumThis[i])<<8 | uint16(sumThis[i+1])
		sum += uint32(nextWord)
	}
	if lenSumThis%2 != 0 {
		// fmt.Println("Odd byte")
		sum += uint32(sumThis[len(sumThis)-1])
	}

	// Add back any carry, and any carry from adding the carry
	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)

	// Bitwise complement
	return uint16(^sum)
}
