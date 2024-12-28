package tunnel

import (
	"encoding/binary"
	"io"
	"net"
	"reverseproxy/crypto"
)

type Tunnel struct {
	conn      net.Conn
	encryptor crypto.Encryptor
}

func NewTunnel(conn net.Conn, encryptor crypto.Encryptor) *Tunnel {
	return &Tunnel{
		conn:      conn,
		encryptor: encryptor,
	}
}

func (t *Tunnel) Write(data []byte) error {
	encrypted, err := t.encryptor.Encrypt(data)
	if err != nil {
		return err
	}

	size := make([]byte, 4)
	binary.BigEndian.PutUint32(size, uint32(len(encrypted)))

	if _, err := t.conn.Write(size); err != nil {
		return err
	}

	_, err = t.conn.Write(encrypted)
	return err
}

func (t *Tunnel) Read() ([]byte, error) {
	sizeBuf := make([]byte, 4)
	if _, err := io.ReadFull(t.conn, sizeBuf); err != nil {
		return nil, err
	}

	size := binary.BigEndian.Uint32(sizeBuf)
	encrypted := make([]byte, size)

	if _, err := io.ReadFull(t.conn, encrypted); err != nil {
		return nil, err
	}

	return t.encryptor.Decrypt(encrypted)
}

func (t *Tunnel) Close() error {
	return t.conn.Close()
}
