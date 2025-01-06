package main

import (
	"crypto/cipher"
	"crypto/rc4"
	"encoding/hex"
	"flag"
	"github.com/NumberMan1/binaryext"
	"log"
	"math/rand"
	"net"
	"time"

	dh64 "github.com/NumberMan1/encrypt/dh64/go"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:10010", "server address")
	flag.Parse()

	lsn, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Print("listen failed: ", err)
		return
	}
	log.Print("server wait")

	for {
		conn, err := lsn.Accept()
		if err != nil {
			log.Print("accept failed: ", err)
			return
		}
		log.Print("server accpet: ", conn.RemoteAddr())

		go func() {
			writer, reader, err := conn_init(conn)
			if err != nil {
				log.Print("conn init failed: ", err)
				return
			}

			var (
				lastPrintTime   = time.Now()
				sendPacketCount uint64
				recvPacketCount uint64
			)

			for {
				var length = int(reader.ReadUint16LE())
				recv := reader.ReadBytes(length)
				if reader.Error() != nil {
					log.Print("receive failed: ", reader.Error())
					return
				}
				recvPacketCount += 1

				writer.WriteUint16LE(uint16(len(recv)))
				writer.WriteBytes(recv)
				if writer.Error() != nil {
					log.Print("send failed: ", writer.Error())
					return
				}
				sendPacketCount += 1

				if time.Since(lastPrintTime) > time.Second*2 {
					lastPrintTime = time.Now()
					log.Print("server: ", recvPacketCount, sendPacketCount)
				}
			}
		}()
	}
}

// Do DH64 key exchange and return a RC4 reader.
func conn_init(conn net.Conn) (*binaryext.Writer, *binaryext.Reader, error) {
	var (
		writer = binaryext.NewWriter(conn)
		reader = binaryext.NewReader(conn)
	)

	rand.Seed(time.Now().UnixNano())

	privateKey, publicKey := dh64.KeyPair()
	log.Print("server public key: ", publicKey)

	writer.WriteUint64LE(publicKey)
	if writer.Error() != nil {
		return nil, nil, writer.Error()
	}
	clientPublicKey := reader.ReadUint64LE()
	if reader.Error() != nil {
		return nil, nil, reader.Error()
	}
	log.Print("client public key: ", clientPublicKey)

	secert := dh64.Secret(privateKey, clientPublicKey)
	log.Print("secert: ", secert)

	key := make([]byte, 8)
	binaryext.PutUint64LE(key, secert)
	rc4stream, err := rc4.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	log.Print("key: ", hex.EncodeToString(key))

	reader = binaryext.NewReader(cipher.StreamReader{
		R: conn,
		S: rc4stream,
	})
	return writer, reader, nil
}
