package client

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"reverseproxy/crypto"
	"reverseproxy/tunnel"

	"github.com/spf13/cobra"
)

// 定义 msgTypeNewConn 和 msgTypeData
const (
	msgTypeNewConn = uint8(1) // 新连接请求
	msgTypeData    = uint8(2) // 数据传输
)

// 定义 Connection 结构体
type Connection struct {
	id         uint32
	targetConn net.Conn
}

// 代理客户端
type ProxyClient struct {
	serverHost  string
	tunnelPort  int
	encryptor   Encryptor
	activeConns sync.Map // 活跃的连接映射，key为connID
}

// 添加 Encryptor 接口和 AESEncryptor 结构体
// 加密相关结构和方法
type Encryptor interface {
	Encrypt([]byte) ([]byte, error)
	Decrypt([]byte) ([]byte, error)
}

type AESEncryptor struct {
	key []byte
}

func NewAESEncryptor(key []byte) (*AESEncryptor, error) {
	if len(key) != 32 {
		key = padKey(key, 32)
	}
	return &AESEncryptor{key: key}, nil
}

func padKey(key []byte, size int) []byte {
	padded := make([]byte, size)
	copy(padded, key)
	return padded
}

func (a *AESEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func (a *AESEncryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, err
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

var (
	key        string
	serverHost string
	tunnelPort int
)

func RunClient(cmd *cobra.Command, args []string) {
	// 获取命令行参数
	serverHost, err := cmd.Flags().GetString("server")
	if err != nil {
		log.Fatal(err)
	}
	tunnelPort, err := cmd.Flags().GetInt("tunnel")
	if err != nil {
		log.Fatal(err)
	}
	key, err := cmd.Flags().GetString("key")
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("serverHost: %s, tunnelPort: %d, key: %s", serverHost, tunnelPort, key)

	encryptor, err := crypto.NewAESEncryptor([]byte(key))
	if err != nil {
		log.Fatal(err)
	}

	client := &ProxyClient{
		serverHost: serverHost,
		tunnelPort: tunnelPort,
		encryptor:  encryptor,
	}

	for {
		if err := client.connectToServer(); err != nil {
			log.Printf("连接服务器失败: %v, 5秒后重试\n", err)
			time.Sleep(5 * time.Second)
			continue
		}
	}
}

func (c *ProxyClient) connectToServer() error {
	// 连接到服务器
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", c.serverHost, c.tunnelPort))
	if err != nil {
		return err
	}
	defer conn.Close()

	log.Printf("已连接到服务器 %s:%d\n", c.serverHost, c.tunnelPort)

	tunnel := tunnel.NewTunnel(conn, c.encryptor)

	// 处理来��服务器的请求
	for {
		data, err := tunnel.Read()
		if err != nil {
			return fmt.Errorf("读取服务器数据错误: %v", err)
		}

		if len(data) == 0 {
			continue
		}

		// 根据消息类型处理
		switch data[0] {
		case msgTypeNewConn:
			// 同步处理新连接请求，确保响应能够及时发送
			c.handleNewConnection(data[1:], tunnel)
		case msgTypeData:
			// 处理数据消息
			if len(data) < 5 {
				log.Printf("无效的数据消息: ��据太短\n")
				continue
			}
			connID := binary.BigEndian.Uint32(data[1:5])
			if conn, ok := c.activeConns.Load(connID); ok {
				if activeConn, ok := conn.(*Connection); ok {
					if _, err := activeConn.targetConn.Write(data[5:]); err != nil {
						log.Printf("[连接 %d] 写入目标��务数据错误: %v\n", connID, err)
					}
				}
			}
		default:
			log.Printf("未知的消息类型: %d\n", data[0])
		}
	}
}

// 添加 handleNewConnection 方法
func (c *ProxyClient) handleNewConnection(data []byte, controlTunnel *tunnel.Tunnel) {
	log.Printf("收到新连接请求，数据长度: %d", len(data))

	if len(data) < 7 { // 至少需要 connID(4) + ver(1) + cmd(1) + atyp(1)
		log.Printf("无效的连接请求: 数据太短\n")
		return
	}

	connID := binary.BigEndian.Uint32(data[:4])
	socks5Req := data[4:] // 完整的 SOCKS5 请求

	log.Printf("SOCKS5请求数据(hex): % x", socks5Req)
	log.Printf("SOCKS5请求解析: VER=%d, CMD=%d, RSV=%d, ATYP=%d",
		socks5Req[0], socks5Req[1], socks5Req[2], socks5Req[3])

	// 解析 SOCKS5 请求
	if socks5Req[0] != 5 {
		log.Printf("不支持的 SOCKS 版本: %d\n", socks5Req[0])
		return
	}

	// 获取目标地址和端口
	var addr string
	var port uint16
	idx := 3 // 跳过 VER, CMD, RSV

	log.Printf("开始解析地址，剩余数据长度: %d", len(socks5Req[idx:]))

	switch socks5Req[idx] {
	case 1: // IPv4
		if len(socks5Req[idx:]) < 7 { // atyp(1) + ip(4) + port(2)
			log.Printf("IPv4数据不完整: 需要7字节，实际%d字节", len(socks5Req[idx:]))
			return
		}
		ip := net.IPv4(socks5Req[idx+1], socks5Req[idx+2], socks5Req[idx+3], socks5Req[idx+4])
		addr = ip.String()
		port = binary.BigEndian.Uint16(socks5Req[idx+5 : idx+7])
	case 3: // Domain
		if len(socks5Req[idx:]) < 2 {
			log.Printf("域名长度数据不完整: 剩余%d字节", len(socks5Req[idx:]))
			return
		}
		domainLen := int(socks5Req[idx+1])
		log.Printf("域名长度字节: %d", domainLen)
		if domainLen > 255 {
			log.Printf("域名长度异常: %d", domainLen)
			return
		}
		expectedLen := 1 + domainLen + 2 // lenByte(1) + domain(domainLen) + port(2)
		if len(socks5Req[idx:]) < expectedLen {
			log.Printf("域名数据不完整: 需要%d字节，实际%d字节",
				expectedLen, len(socks5Req[idx:]))
			return
		}
		addr = string(socks5Req[idx+2 : idx+2+domainLen])
		if strings.Contains(addr, "\x00") {
			log.Printf("域名包含空字符")
			return
		}
		log.Printf("解析到域名: %s", addr)
		port = binary.BigEndian.Uint16(socks5Req[idx+2+domainLen : idx+2+domainLen+2])
	case 4: // IPv6
		if len(socks5Req[idx:]) < 19 { // atyp(1) + ip(16) + port(2)
			log.Printf("IPv6数据不完整: 需要19字节，实际%d字节", len(socks5Req[idx:]))
			return
		}
		ip := net.IP(socks5Req[idx+1 : idx+17])
		addr = ip.String()
		port = binary.BigEndian.Uint16(socks5Req[idx+17 : idx+19])
	default:
		log.Printf("不支持的地址类型: %d\n", socks5Req[idx])
		return
	}

	log.Printf("收到连接请求 ID: %d, 目标: %s:%d\n", connID, addr, port)

	// 连接目标服务器
	targetConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", addr, port))
	if err != nil {
		log.Printf("[连接 %d] 连接目标服务器失败: %v\n", connID, err)
		return
	}

	// 存储连接
	c.activeConns.Store(connID, &Connection{
		id:         connID,
		targetConn: targetConn,
	})

	log.Printf("建立连接ID: %d 到目标: %s:%d\n", connID, addr, port)

	// 发送连接成功响应给服务器
	response := make([]byte, 5)
	response[0] = msgTypeNewConn
	binary.BigEndian.PutUint32(response[1:5], connID)
	if err := controlTunnel.Write(response); err != nil {
		log.Printf("发送连接响应失败: %v\n", err)
		targetConn.Close()
		c.activeConns.Delete(connID)
		return
	}

	// 启动数据转发
	go func() {
		defer func() {
			targetConn.Close()
			c.activeConns.Delete(connID)
			log.Printf("[连接 %d] 已关闭\n", connID)
		}()

		buf := make([]byte, 4096)
		for {
			n, err := targetConn.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Printf("[连接 %d] 读取目标服务器数据错误: %v\n", connID, err)
				}
				return
			}

			message := append([]byte{msgTypeData}, make([]byte, 4)...)
			binary.BigEndian.PutUint32(message[1:5], connID)
			message = append(message, buf[:n]...)

			if err := controlTunnel.Write(message); err != nil {
				log.Printf("[连接 %d] 发送数据到隧道错误: %v\n", connID, err)
				return
			}
		}
	}()
}
