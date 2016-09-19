package miniss

import (
	"bytes"
	"io"
	"net"

	"gopkg.in/bunsim/natrium.v1"
)

// Handshake upgrades a plaintext socket to a MiniSS socket, given our secret key.
func Handshake(plain net.Conn, mysk natrium.ECDHPrivate) (sok *Socket, err error) {
	// generate ephemeral key
	myesk := natrium.ECDHGenerateKey()
	// in another thread, send over hello
	wet := make(chan bool)
	go func() {
		var msgb bytes.Buffer
		msgb.Write([]byte("MiniSS-1"))
		msgb.Write(mysk.PublicKey())
		msgb.Write(myesk.PublicKey())
		io.Copy(plain, &msgb)
		close(wet)
	}()
	// read hello
	bts := make([]byte, 64+8)
	_, err = io.ReadFull(plain, bts)
	if err != nil {
		return
	}
	// check version
	if string(bts[:8]) != "MiniSS-1" {
		err = io.ErrClosedPipe
		return
	}
	// read rest of hello
	bts = bts[8:]
	<-wet
	ripk := natrium.ECDHPublic(bts[:32])
	repk := natrium.ECDHPublic(bts[32:])
	return newSocket(plain, mysk, myesk, ripk, repk)
}
