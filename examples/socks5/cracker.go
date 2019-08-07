package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"scanner"
)

type cracker struct {
	address    <-chan string
	dialer     *scanner.Dialer
	stopSignal <-chan struct{}
	wg         *sync.WaitGroup
}

func (c *cracker) Do() {
	defer c.wg.Done()
	var (
		address string
		err     error
	)
	for {
		select {
		case address = <-c.address:
			if address == "" {
				return
			}
			err = c.connectSocks5(address, "", "")
			if err == nil {
				log.Print(address + "\r\n")
			}
		case <-c.stopSignal:
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
)

var (
	errNoAcceptableMethods = errors.New("no acceptable authentication methods")
)

func (c *cracker) connectSocks5(address, username, password string) error {
	conn, err := c.dialer.Dial("tcp", address)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(2 * timeout))
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
		_, err := conn.Write(buffer.Bytes())
		if err != nil {
			return err
		}
		response := make([]byte, 2)
		_, err = io.ReadFull(conn, response)
		if err != nil {
			return err
		}
		if response[0] != usernamePasswordVersion {
			return errors.New("invalid username/password version")
		}
		if response[1] != statusSucceeded {
			return errors.New("invalid username/password")
		}
	default:
		return fmt.Errorf("unsupported authentication method %d", am)
	}
	return nil
}
