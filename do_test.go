package miniss

import (
	"io"
	"log"
	"net"
	"testing"

	"gopkg.in/bunsim/cluttershirt.v1"

	"gopkg.in/bunsim/natrium.v1"
)

func BenchmarkMiniSS(b *testing.B) {
	bigsk := natrium.ECDHGenerateKey()
	log.Printf("%x", bigsk.PublicKey())
	go func() {
		lsnr, _ := net.Listen("tcp", "127.0.0.1:13371")
		for {
			clnt, _ := lsnr.Accept()
			go func() {
				defer clnt.Close()
				var err error
				clnt, err = cluttershirt.Server(make([]byte, 32), clnt)
				sok, err := Handshake(clnt, bigsk)
				if err != nil {
					panic(err.Error())
				}
				io.Copy(sok, sok)
			}()
		}
	}()
	lsnr, _ := net.Listen("tcp", "127.0.0.1:13370")
	for {
		clnt, _ := lsnr.Accept()
		go func() {
			defer clnt.Close()
			plain, err := net.Dial("tcp", "127.0.0.1:13371")
			if err != nil {
				panic(err.Error())
			}
			plain, err = cluttershirt.Client(make([]byte, 32), plain)
			crypt, err := Handshake(plain, natrium.ECDHGenerateKey())
			if err != nil {
				panic(err.Error())
			}
			log.Printf("%x", crypt.RemotePK())
			defer crypt.Close()
			go func() {
				defer crypt.Close()
				defer clnt.Close()
				io.Copy(crypt, clnt)
			}()
			io.Copy(clnt, crypt)
		}()
	}
}
