package miniss

import (
	"io"
	"net"
	"testing"

	"gopkg.in/bunsim/natrium.v1"
)

func BenchmarkMiniSS(b *testing.B) {
	bigsk := natrium.ECDHGenerateKey()
	go func() {
		lsnr, _ := net.Listen("tcp", "127.0.0.1:13371")
		for {
			clnt, _ := lsnr.Accept()
			go func() {
				defer clnt.Close()
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
			crypt, err := Handshake(plain, natrium.ECDHGenerateKey())
			if err != nil {
				panic(err.Error())
			}
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
