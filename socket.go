package miniss

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"io"
	"net"
	"time"

	"gopkg.in/bunsim/natrium.v1"
)

// Socket represents a MiniSS connection; it implements net.Conn but with more methods.
type Socket struct {
	rxctr   uint64
	rxerr   error
	rxcrypt cipher.AEAD
	rxbuf   bytes.Buffer

	txctr   uint64
	txcrypt cipher.AEAD

	plain  net.Conn
	locIsk natrium.ECDHPrivate
	locEsk natrium.ECDHPrivate
	remIpk natrium.ECDHPublic
	remEpk natrium.ECDHPublic
}

func newSocket(plain net.Conn, lisk, lesk natrium.ECDHPrivate, ripk, repk natrium.ECDHPublic) (sok *Socket, err error) {
	// calculate shared secrets
	ss := natrium.TripleECDH(lisk, ripk, lesk, repk)
	s1 := natrium.SecureHash(ss, []byte("miniss-s1"))
	s2 := natrium.SecureHash(ss, []byte("miniss-s2"))
	// derive keys
	var rxkey []byte
	var txkey []byte
	if natrium.CTCompare(lesk.PublicKey(), repk) == -1 {
		rxkey = s1
		txkey = s2
	} else {
		txkey = s1
		rxkey = s2
	}
	// create socket
	sok = &Socket{
		rxcrypt: natrium.AEAD(rxkey),
		txcrypt: natrium.AEAD(txkey),
		plain:   plain,
		locIsk:  lisk,
		locEsk:  lesk,
		remIpk:  ripk,
		remEpk:  repk,
	}
	// check that everything went well
	go func() {
		sok.Write(make([]byte, 16))
	}()
	_, err = sok.Read(make([]byte, 16))
	return
}

// LocalSK returns the local long-term secret key.
func (sk *Socket) LocalSK() natrium.ECDHPrivate {
	return sk.locIsk
}

// RemotePK returns the remote long-term public key.
func (sk *Socket) RemotePK() natrium.ECDHPublic {
	return sk.remIpk
}

// Read reads into the given byte slice.
func (sk *Socket) Read(p []byte) (n int, err error) {
	// if any in buffer, read from buffer
	if sk.rxbuf.Len() > 0 {
		return sk.rxbuf.Read(p)
	}
	// if error exists, return it
	err = sk.rxerr
	if err != nil {
		return
	}
	// otherwise wait for record
	lenbts := make([]byte, 2)
	_, err = io.ReadFull(sk.plain, lenbts)
	if err != nil {
		sk.rxerr = err
		return
	}
	ciph := make([]byte, binary.BigEndian.Uint16(lenbts))
	_, err = io.ReadFull(sk.plain, ciph)
	if err != nil {
		sk.rxerr = err
		return
	}
	// decrypt the ciphertext
	nonce := make([]byte, 8)
	binary.BigEndian.PutUint64(nonce, sk.rxctr)
	sk.rxctr++
	data, err := sk.rxcrypt.Open(nil, nonce, ciph, nil)
	if err != nil {
		sk.rxerr = err
		return
	}
	// copy the data into the buffer
	n = copy(p, data)
	if n < len(p) {
		sk.rxbuf.Write(p[n:])
	}
	return
}

// Write writes out the given byte slice. No guarantees are made regarding the number of low-level segments sent over the wire.
func (sk *Socket) Write(p []byte) (n int, err error) {
	if len(p) > 32768 {
		// recurse
		var n1 int
		var n2 int
		n1, err = sk.Write(p[:32768])
		if err != nil {
			return
		}
		n2, err = sk.Write(p[32768:])
		if err != nil {
			return
		}
		n = n1 + n2
		return
	}
	// main work here
	nonce := make([]byte, 8)
	binary.BigEndian.PutUint64(nonce, sk.txctr)
	sk.txctr++
	ciph := sk.txcrypt.Seal(nil, nonce, p, nil)
	lenbts := make([]byte, 2)
	binary.BigEndian.PutUint16(lenbts, uint16(len(ciph)))
	_, err = sk.plain.Write(append(lenbts, ciph...))
	n = len(p)
	return
}

// Close closes the socket.
func (sk *Socket) Close() error {
	return sk.plain.Close()
}

// LocalAddr returns the local address.
func (sk *Socket) LocalAddr() net.Addr {
	return sk.plain.LocalAddr()
}

// RemoteAddr returns the remote address.
func (sk *Socket) RemoteAddr() net.Addr {
	return sk.plain.RemoteAddr()
}

// SetDeadline sets the deadline.
func (sk *Socket) SetDeadline(t time.Time) error {
	return sk.plain.SetDeadline(t)
}

// SetReadDeadline sets the read deadline.
func (sk *Socket) SetReadDeadline(t time.Time) error {
	return sk.plain.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline.
func (sk *Socket) SetWriteDeadline(t time.Time) error {
	return sk.plain.SetWriteDeadline(t)
}
