package tunnel

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"reverseproxy/crypto"
)

// Tunnel 代理隧道
type Tunnel struct {
	conn      net.Conn
	encryptor crypto.Encryptor
	writeMu   sync.Mutex
	readMu    sync.Mutex
	ready     bool
}

// NewTunnel 创建新的隧道
func NewTunnel(conn net.Conn, encryptor crypto.Encryptor) *Tunnel {
	return &Tunnel{
		conn:      conn,
		encryptor: encryptor,
		ready:     false,
	}
}

// Handshake 执行隧道握手
func (t *Tunnel) Handshake(isServer bool) error {
	if isServer {
		// 服务器等待客户端的握手消息
		msg, err := t.ReadMessage()
		if err != nil {
			return fmt.Errorf("读取握手消息失败: %v", err)
		}
		if msg.Header.Type != MessageTypeHeartbeat {
			return fmt.Errorf("无效的握手消息类型")
		}

		// 发送响应
		response := NewHeartbeatMessage()
		if err := t.WriteMessage(response); err != nil {
			return fmt.Errorf("发送握手响应失败: %v", err)
		}
	} else {
		// 客户端发送握手消息
		msg := NewHeartbeatMessage()
		if err := t.WriteMessage(msg); err != nil {
			return fmt.Errorf("发送握手消息失败: %v", err)
		}

		// 等待服务器响应
		response, err := t.ReadMessage()
		if err != nil {
			return fmt.Errorf("读取握手响应失败: %v", err)
		}
		if response.Header.Type != MessageTypeHeartbeat {
			return fmt.Errorf("无效的握手响应类型")
		}
	}

	t.ready = true
	return nil
}

// WriteMessage 写入消息
func (t *Tunnel) WriteMessage(msg *Message) error {
	if !t.ready {
		return fmt.Errorf("隧道未就绪")
	}

	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	// 编码消息
	data := EncodeMessage(msg)

	// 加密数据
	encrypted, err := t.encryptor.Encrypt(data)
	if err != nil {
		return fmt.Errorf("加密数据失败: %v", err)
	}

	// 写入数据长度
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(encrypted)))
	if _, err := t.conn.Write(lenBuf); err != nil {
		return fmt.Errorf("写入数据长度失败: %v", err)
	}

	// 写入加密数据
	if _, err := t.conn.Write(encrypted); err != nil {
		return fmt.Errorf("写入加密数据失败: %v", err)
	}

	return nil
}

// ReadMessage 读取消息
func (t *Tunnel) ReadMessage() (*Message, error) {
	if !t.ready {
		return nil, fmt.Errorf("隧道未就绪")
	}

	t.readMu.Lock()
	defer t.readMu.Unlock()

	// 读取数据长度
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(t.conn, lenBuf); err != nil {
		return nil, fmt.Errorf("读取数据长度失败: %v", err)
	}

	dataLen := binary.BigEndian.Uint32(lenBuf)
	if dataLen > 1024*1024 { // 限制最大数据包大小为1MB
		return nil, fmt.Errorf("数据包过大: %d", dataLen)
	}

	// 读取加密数据
	encrypted := make([]byte, dataLen)
	if _, err := io.ReadFull(t.conn, encrypted); err != nil {
		return nil, fmt.Errorf("读取加密数据失败: %v", err)
	}

	// 解密数据
	decrypted, err := t.encryptor.Decrypt(encrypted)
	if err != nil {
		return nil, fmt.Errorf("解密数据失败: %v", err)
	}

	// 解析消息
	msg, err := ParseMessage(decrypted)
	if err != nil {
		return nil, fmt.Errorf("解析消息失败: %v", err)
	}

	return msg, nil
}

// Close 关闭隧道
func (t *Tunnel) Close() error {
	t.ready = false
	return t.conn.Close()
}

// SetReadDeadline 设置读取超时
func (t *Tunnel) SetReadDeadline(deadline time.Time) error {
	return t.conn.SetReadDeadline(deadline)
}

// SetWriteDeadline 设置写入超时
func (t *Tunnel) SetWriteDeadline(deadline time.Time) error {
	return t.conn.SetWriteDeadline(deadline)
}

// IsReady 检查隧道是否就绪
func (t *Tunnel) IsReady() bool {
	return t.ready
}

// GetConn 获取底层连接
func (t *Tunnel) GetConn() net.Conn {
	return t.conn
}
