package tunnel

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"reverseproxy/crypto"

	"github.com/xtaci/kcp-go"
)

// Tunnel 表示一个加密通信隧道
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
		data := make([]byte, 4)
		if _, err := io.ReadFull(t.conn, data); err != nil {
			return fmt.Errorf("读取握手消息失败: %v", err)
		}
		if string(data) != "HELO" {
			return fmt.Errorf("无效的握手消息")
		}

		// 发送响应
		if _, err := t.conn.Write([]byte("HELO")); err != nil {
			return fmt.Errorf("发送握手响应失败: %v", err)
		}
	} else {
		// 客户端发送握手消息
		if _, err := t.conn.Write([]byte("HELO")); err != nil {
			return fmt.Errorf("发送握手消息失败: %v", err)
		}

		// 等待服务器响应
		data := make([]byte, 4)
		if _, err := io.ReadFull(t.conn, data); err != nil {
			return fmt.Errorf("读取握手响应失败: %v", err)
		}
		if string(data) != "HELO" {
			return fmt.Errorf("无效的握手响应")
		}
	}

	t.ready = true
	return nil
}

// Write 写入加密数据
func (t *Tunnel) Write(data []byte) error {
	if !t.ready {
		return fmt.Errorf("隧道未就绪")
	}

	t.writeMu.Lock()
	defer t.writeMu.Unlock()

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

// Read 读取并解密数据
func (t *Tunnel) Read() ([]byte, error) {
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

	return decrypted, nil
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

// KCPConfig KCP配置
type KCPConfig struct {
	MTU          int // 最大传输单元
	SndWnd       int // 发送窗口大小
	RcvWnd       int // 接收窗口大小
	NoDelay      int // 是否启用 nodelay模式
	Interval     int // 内部更新时钟，毫秒
	Resend       int // 快速重传模式
	NoCongestion int // 是否禁用拥塞控制
}

// DefaultKCPConfig 返回默认的KCP配置
func DefaultKCPConfig() *KCPConfig {
	return &KCPConfig{
		MTU:          1400,
		SndWnd:       1024,
		RcvWnd:       1024,
		NoDelay:      1,
		Interval:     10,
		Resend:       2,
		NoCongestion: 1,
	}
}

// ApplyKCPConfig 应用KCP配置到连接
func ApplyKCPConfig(conn *kcp.UDPSession, config *KCPConfig) {
	if config == nil {
		config = DefaultKCPConfig()
	}

	conn.SetMtu(config.MTU)
	conn.SetWindowSize(config.SndWnd, config.RcvWnd)
	conn.SetNoDelay(config.NoDelay, config.Interval, config.Resend, config.NoCongestion)
}
