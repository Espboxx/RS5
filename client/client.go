package client

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"reverseproxy/crypto"
	"reverseproxy/logger"
	"reverseproxy/tunnel"

	"github.com/xtaci/kcp-go"
)

// connection 表示一个活跃的连接
type connection struct {
	id         uint32
	targetConn net.Conn
	lastActive time.Time
}

// Client 客户端结构体
type Client struct {
	serverAddr   string
	protocol     string
	encryptor    crypto.Encryptor
	tunnel       *tunnel.Tunnel
	kcpConfig    *tunnel.KCPConfig
	done         chan struct{}
	activeConns  sync.Map
	nextConnID   uint32
	readTimeout  time.Duration
	writeTimeout time.Duration
	udpConns     sync.Map
}

// NewClient 创建新的客户端
func NewClient(serverAddr string, key []byte, protocol string) (*Client, error) {
	encryptor, err := crypto.NewAESEncryptor(key)
	if err != nil {
		return nil, fmt.Errorf("创建加密器失败: %v", err)
	}

	return &Client{
		serverAddr:   serverAddr,
		protocol:     protocol,
		encryptor:    encryptor,
		kcpConfig:    tunnel.DefaultKCPConfig(),
		done:         make(chan struct{}),
		readTimeout:  30 * time.Second,
		writeTimeout: 30 * time.Second,
	}, nil
}

// Start 启动客户端
func (c *Client) Start() error {
	// 连接到服务器
	var conn net.Conn
	var err error

	if c.protocol == "kcp" {
		// 使用KCP协议
		kcpConn, err := kcp.DialWithOptions(c.serverAddr, nil, 10, 3)
		if err != nil {
			return fmt.Errorf("KCP连接服务器失败: %v", err)
		}
		// 设置基础的KCP参数
		if err := kcpConn.SetDSCP(46); err != nil {
			logger.Warn("设置KCP DSCP失败: %v", err)
		}
		if err := kcpConn.SetReadBuffer(4194304); err != nil {
			logger.Warn("设置KCP读缓冲区失败: %v", err)
		}
		if err := kcpConn.SetWriteBuffer(4194304); err != nil {
			logger.Warn("设置KCP写缓冲区失败: %v", err)
		}
		// 应用KCP���置
		tunnel.ApplyKCPConfig(kcpConn, c.kcpConfig)
		logger.Debug("已应用KCP配置: MTU=%d, 窗口大小=%d/%d",
			c.kcpConfig.MTU, c.kcpConfig.SndWnd, c.kcpConfig.RcvWnd)
		conn = kcpConn
	} else {
		conn, err = net.DialTimeout("tcp", c.serverAddr, c.readTimeout)
		if err != nil {
			return fmt.Errorf("TCP连接服务器失败: %v", err)
		}
	}

	// 创建隧道
	c.tunnel = tunnel.NewTunnel(conn, c.encryptor)

	// 执行隧道握手
	if err := c.tunnel.Handshake(false); err != nil {
		return fmt.Errorf("隧道握手失败: %v", err)
	}

	// 启动心跳
	go c.heartbeat()

	// 处理隧道消息
	go c.handleTunnelMessages()

	logger.Info("已连接到服务器: %s", c.serverAddr)

	// 等待退出信号
	<-c.done

	return nil
}

// heartbeat 发送心跳包
func (c *Client) heartbeat() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			// 发送心跳包
			heartbeat := []byte{0} // 0表示心跳包
			if err := c.tunnel.Write(heartbeat); err != nil {
				logger.Error("发送心跳包失败: %v", err)
				return
			}
		}
	}
}

// handleTunnelMessages 处理隧道消息
func (c *Client) handleTunnelMessages() {
	for {
		select {
		case <-c.done:
			return
		default:
			// 读取消息
			data, err := c.tunnel.Read()
			if err != nil {
				logger.Error("读取隧道消息失败: %v", err)
				return
			}

			if len(data) == 0 {
				continue
			}

			// 处理消息
			switch data[0] {
			case 0: // 心跳包
				continue
			case 1: // 新连接请求
				if err := c.handleNewConnection(data[1:]); err != nil {
					logger.Error("处理新连接请求失败: %v", err)
				}
			case 2: // 数据转发
				if err := c.handleData(data[1:]); err != nil {
					logger.Error("处理数据转发失败: %v", err)
				}
			case 3: // UDP数据包
				if err := c.handleUDPData(data[1:]); err != nil {
					logger.Error("处理UDP数据失败: %v", err)
				}
			default:
				logger.Error("未知消息类型: %d", data[0])
			}
		}
	}
}

// handleNewConnection 处理新连接请求
func (c *Client) handleNewConnection(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("新连接数据长度不足")
	}

	// 解析连接ID和目标地址
	connID := binary.BigEndian.Uint32(data[:4])
	targetAddr := string(data[4:])

	// 连接到目标地址
	targetConn, err := net.DialTimeout("tcp", targetAddr, c.readTimeout)
	if err != nil {
		// 发送连接失败响应
		response := make([]byte, 5)
		response[0] = 1 // 新连接响应
		binary.BigEndian.PutUint32(response[1:], connID)
		if err := c.tunnel.Write(response); err != nil {
			logger.Error("发送连接失败响应失败: %v", err)
		}
		return fmt.Errorf("连接目标地址失败: %v", err)
	}

	// 创建连接对象
	conn := &connection{
		id:         connID,
		targetConn: targetConn,
		lastActive: time.Now(),
	}

	// 存储连接
	c.activeConns.Store(connID, conn)

	logger.Debug("新建连接 %d -> %s", connID, targetAddr)

	// 发送连接成功响应
	response := make([]byte, 5)
	response[0] = 1 // 新连接响应
	binary.BigEndian.PutUint32(response[1:], connID)
	if err := c.tunnel.Write(response); err != nil {
		targetConn.Close()
		c.activeConns.Delete(connID)
		return fmt.Errorf("发送连接成功响应失败: %v", err)
	}

	// 启动数据转发
	go c.forwardData(conn)

	return nil
}

// handleData 处理数据转发
func (c *Client) handleData(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("数据长度不足")
	}

	// 解析连接ID
	connID := binary.BigEndian.Uint32(data[:4])
	payload := data[4:]

	// 获取连接
	connInterface, ok := c.activeConns.Load(connID)
	if !ok {
		return fmt.Errorf("未找到连接: %d", connID)
	}

	conn := connInterface.(*connection)
	conn.lastActive = time.Now()

	// 发送数据到目标连接
	if _, err := conn.targetConn.Write(payload); err != nil {
		c.cleanupConnection(connID)
		return fmt.Errorf("发送数据到目标连接失败: %v", err)
	}

	return nil
}

// forwardData 转发目标连接的数据到隧道
func (c *Client) forwardData(conn *connection) {
	defer c.cleanupConnection(conn.id)

	buffer := make([]byte, 32*1024)
	for {
		// 读取目标连接数据
		n, err := conn.targetConn.Read(buffer)
		if err != nil {
			if err != io.EOF {
				logger.Error("读取目标连接数据失败: %v", err)
			}
			return
		}

		// 准备转发数据
		data := make([]byte, n+5)
		data[0] = 2 // 数据转发
		binary.BigEndian.PutUint32(data[1:5], conn.id)
		copy(data[5:], buffer[:n])

		// 发送数据到隧道
		if err := c.tunnel.Write(data); err != nil {
			logger.Error("发送数据到隧道失败: %v", err)
			return
		}

		conn.lastActive = time.Now()
	}
}

// cleanupConnection 清理连接
func (c *Client) cleanupConnection(connID uint32) {
	if conn, ok := c.activeConns.Load(connID); ok {
		activeConn := conn.(*connection)
		activeConn.targetConn.Close()
		c.activeConns.Delete(connID)
		logger.Debug("清理连接 %d", connID)
	}
}

// udpConn UDP连接结构体
type udpConn struct {
	conn       *net.UDPConn
	targetAddr *net.UDPAddr
	sourceAddr *net.UDPAddr
	lastActive time.Time
}

// handleUDPData 处理UDP数据
func (c *Client) handleUDPData(data []byte) error {
	if len(data) < 9 { // 至少需要4字节连接ID和5字节源地址
		return fmt.Errorf("UDP数据长度不足")
	}

	// 解析连接ID
	connID := binary.BigEndian.Uint32(data[:4])

	// 解析源地址
	sourceAddrStr := string(data[4:9])
	sourceAddr, err := net.ResolveUDPAddr("udp", sourceAddrStr)
	if err != nil {
		return fmt.Errorf("解析源地址失败: %v", err)
	}

	// 获取或创建UDP连接
	udpConnInterface, ok := c.udpConns.Load(connID)
	if !ok {
		// 创建新的UDP连接
		conn, err := net.ListenUDP("udp", nil)
		if err != nil {
			return fmt.Errorf("创建UDP连接失败: %v", err)
		}

		udpConnInterface = &udpConn{
			conn:       conn,
			sourceAddr: sourceAddr,
			lastActive: time.Now(),
		}
		c.udpConns.Store(connID, udpConnInterface)

		// 启动UDP读取协程
		go c.handleUDPResponse(connID, udpConnInterface.(*udpConn))
	}

	udpConn := udpConnInterface.(*udpConn)
	udpConn.lastActive = time.Now()

	// 发送数据到目标地址
	if _, err := udpConn.conn.Write(data[9:]); err != nil {
		c.cleanupUDPConnection(connID)
		return fmt.Errorf("发送UDP数据失败: %v", err)
	}

	return nil
}

// handleUDPResponse 处理UDP响应
func (c *Client) handleUDPResponse(connID uint32, conn *udpConn) {
	defer c.cleanupUDPConnection(connID)

	buffer := make([]byte, 64*1024)
	for {
		select {
		case <-c.done:
			return
		default:
			// 设置读取超时
			conn.conn.SetReadDeadline(time.Now().Add(c.readTimeout))

			// 读取UDP数据
			n, _, err := conn.conn.ReadFromUDP(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// 超时检查连接是否仍然活跃
					if time.Since(conn.lastActive) > c.readTimeout {
						return
					}
					continue
				}
				logger.Error("读取UDP响应失败: %v", err)
				return
			}

			// 准备响应数据
			data := make([]byte, n+5)
			data[0] = 3 // UDP数据包
			binary.BigEndian.PutUint32(data[1:5], connID)
			copy(data[5:], buffer[:n])

			// 发送到隧道
			if err := c.tunnel.Write(data); err != nil {
				logger.Error("发送UDP响应到隧道失败: %v", err)
				return
			}

			conn.lastActive = time.Now()
		}
	}
}

// cleanupUDPConnection 清理UDP连接
func (c *Client) cleanupUDPConnection(connID uint32) {
	if conn, ok := c.udpConns.Load(connID); ok {
		udpConn := conn.(*udpConn)
		udpConn.conn.Close()
		c.udpConns.Delete(connID)
		logger.Debug("清理UDP连接 %d", connID)
	}
}

// Close 关闭客户端
func (c *Client) Close() error {
	close(c.done)

	// 关闭所有活跃连接
	c.activeConns.Range(func(key, value interface{}) bool {
		if conn, ok := value.(*connection); ok {
			conn.targetConn.Close()
		}
		return true
	})

	// 关闭所有UDP连接
	c.udpConns.Range(func(key, value interface{}) bool {
		if conn, ok := value.(*udpConn); ok {
			conn.conn.Close()
		}
		return true
	})

	// 关闭隧道
	if c.tunnel != nil {
		return c.tunnel.Close()
	}

	return nil
}
