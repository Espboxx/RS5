package server

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"reverseproxy/crypto"
	"reverseproxy/tunnel"

	"github.com/spf13/cobra"
)

const (
	socks5Version = uint8(5)

	// 认证方法
	authNone = uint8(0)

	// 命令类型
	cmdConnect = uint8(1)

	// 地址类型
	atypIPv4   = uint8(1)
	atypDomain = uint8(3)
	atypIPv6   = uint8(4)

	// 响应状态
	repSuccess         = uint8(0)
	repServerFailure   = uint8(1)
	repHostUnreachable = uint8(4)

	// 添加一个新的消息类型常量
	msgTypeNewConn = uint8(1) // 新连接请求
	msgTypeData    = uint8(2) // 数据传输
)

var (
	key        string
	socksPort  int
	tunnelPort int
)

// 定义 Connection 结构体
type Connection struct {
	id         uint32
	targetConn net.Conn
	lastActive time.Time
	closed     int32
}

// 代理服务器
type ProxyServer struct {
	socksPort    int            // SOCKS5代理端口
	tunnelPort   int            // 隧道端口
	tunnel       *tunnel.Tunnel // 控制隧道连接
	nextConnID   uint32         // 下一个可用的连接ID
	mutex        sync.RWMutex
	encryptor    crypto.Encryptor
	activeConns  sync.Map      // 活跃的连接映射，key为connID
	tunnelReady  chan struct{} // 用于通知隧道就绪的通道
	bufferPool   sync.Pool
	maxConns     int
	currentConns int32
}

func RunServer(cmd *cobra.Command, args []string) {
	// 获取命令行参数
	socksPort, err := cmd.Flags().GetInt("socks")
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

	log.Printf("socksPort: %d, tunnelPort: %d, key: %s", socksPort, tunnelPort, key)

	encryptor, err := crypto.NewAESEncryptor([]byte(key))
	if err != nil {
		log.Fatal(err)
	}

	server := &ProxyServer{
		socksPort:   socksPort,
		tunnelPort:  tunnelPort,
		encryptor:   encryptor,
		tunnelReady: make(chan struct{}),
		bufferPool: sync.Pool{
			New: func() interface{} {
				return make([]byte, 32*1024) // 32KB 缓冲区
			},
		},
		maxConns: 1000, // 最大并发连接数
	}

	// 启动 SOCKS5 服务
	go func() {
		listener, err := net.Listen("tcp", fmt.Sprintf(":%d", server.socksPort))
		if err != nil {
			log.Fatal(err)
		}
		defer listener.Close()

		log.Printf("SOCKS5服务器正在监听端口 %d\n", server.socksPort)

		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("接受SOCKS5连接错误: %v\n", err)
				continue
			}

			go func(conn net.Conn) {
				defer conn.Close()
				if err := handleSocks5(conn, server); err != nil {
					log.Printf("处理SOCKS5连接错误: %v\n", err)
				}
			}(conn)
		}
	}()

	// 启动隧道服务
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", server.tunnelPort))
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	log.Printf("隧道服务器正在监听端口 %d\n", server.tunnelPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("接受隧道连接错误: %v\n", err)
			continue
		}

		go server.handleTunnel(conn)
	}
}

// generateConnID 生成唯一的连接ID
func (s *ProxyServer) generateConnID() uint32 {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.nextConnID++
	return s.nextConnID
}

func handleSocks5(conn net.Conn, server *ProxyServer) error {
	// 检查并发连接数
	if atomic.LoadInt32(&server.currentConns) >= int32(server.maxConns) {
		return fmt.Errorf("达到最大连接数限制")
	}
	atomic.AddInt32(&server.currentConns, 1)
	defer atomic.AddInt32(&server.currentConns, -1)

	// 设置连接超时
	conn.SetDeadline(time.Now().Add(5 * time.Minute))

	// 等待隧道就绪
	log.Printf("等待隧道连接就绪...")
	select {
	case <-server.tunnelReady:
		log.Printf("隧道已就绪，开始处理SOCKS5请求")
	case <-time.After(10 * time.Second):
		log.Printf("等待隧道连接超时")
		return fmt.Errorf("等待隧道连接超时")
	}

	// 1. 握手阶段
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("读取握手头部失败: %v", err)
	}

	if buf[0] != 5 {
		return fmt.Errorf("不支持的 SOCKS 版本: %d", buf[0])
	}

	nMethods := int(buf[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("读取认证方法失败: %v", err)
	}

	// 选择不认证
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return fmt.Errorf("写入认证方法响应失败: %v", err)
	}

	// 2. 请求阶段
	buf = server.bufferPool.Get().([]byte)
	defer server.bufferPool.Put(buf)

	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return fmt.Errorf("读取请求头部失败: %v", err)
	}

	// 读取地址类型
	addrType := buf[3]
	var totalLen int

	log.Printf("SOCKS5请求: VER=%d, CMD=%d, RSV=%d, ATYP=%d",
		buf[0], buf[1], buf[2], buf[3])

	switch addrType {
	case 1: // IPv4
		totalLen = 4 + 2 // IPv4(4) + Port(2)
		log.Printf("地址类型: IPv4, 需要读取长度: %d", totalLen)
		// 读取 IPv4 地址和端口
		if _, err := io.ReadFull(conn, buf[4:4+totalLen]); err != nil {
			return fmt.Errorf("读取 IPv4 地址和端口失败: %v", err)
		}
	case 3: // Domain
		if _, err := io.ReadFull(conn, buf[4:5]); err != nil {
			return fmt.Errorf("读取域名长度失败: %v", err)
		}
		domainLen := int(buf[4])
		if domainLen > 255 {
			return fmt.Errorf("域名长度超出限制: %d", domainLen)
		}
		totalLen = 1 + domainLen + 2 // LenByte(1) + DomainLen + Port(2)
		log.Printf("地址类型: Domain, 域名长度: %d, 总需要读取长度: %d, 域名长度字节(hex): %02x",
			domainLen, totalLen, buf[4])

		// 读取域名和端口
		if _, err := io.ReadFull(conn, buf[5:5+domainLen+2]); err != nil {
			return fmt.Errorf("读取域名和端口失败: %v", err)
		}
		domain := string(buf[5 : 5+domainLen])

		port := binary.BigEndian.Uint16(buf[5+domainLen : 5+domainLen+2])
		log.Printf("解析到域名: %s, 端口: %d", domain, port)
	case 4: // IPv6
		totalLen = 16 + 2 // IPv6(16) + Port(2)
		log.Printf("地址类型: IPv6, 需要读取长度: %d", totalLen)
		// 读取 IPv6 地址和端口
		if _, err := io.ReadFull(conn, buf[4:4+totalLen]); err != nil {
			return fmt.Errorf("读取 IPv6 地址和端口失败: %v", err)
		}
	default:
		return fmt.Errorf("不支持的地址类型: %d", addrType)
	}

	// 打印完整的请求数据
	log.Printf("完整的请求数据(hex): % x", buf[:4+totalLen])

	// 通过隧道将连接请求发送给客户端处理
	connID := server.generateConnID()

	// 构造完整的 SOCKS5 请求消息
	request := append([]byte{msgTypeNewConn}, make([]byte, 4)...)
	binary.BigEndian.PutUint32(request[1:5], connID)
	// 确保只发送实际需要的数据
	request = append(request, buf[:4+totalLen]...)
	log.Printf("发送到客户端的数据(hex): % x", request)
	log.Printf("发送到客户端的完整请求数据长度: %d", len(request))

	if err := server.tunnel.Write(request); err != nil {
		return fmt.Errorf("发送隧道请求失败: %v", err)
	}

	// 发送成功响应
	sendSocks5Response(conn, 0)

	// 将当前连接存储到 activeConns 中
	server.activeConns.Store(connID, &Connection{
		id:         connID,
		targetConn: conn,
	})

	// 等待连接关闭
	<-make(chan struct{})

	return nil
}

// sendSocks5Response 发送 SOCKS5 响应
func sendSocks5Response(conn net.Conn, rep byte) error {
	response := []byte{5, rep, 0, 1, 0, 0, 0, 0, 0, 0} // IPv4 0.0.0.0:0
	_, err := conn.Write(response)
	return err
}

// createTunnelConnection 通过隧道创建新的连接请求
func (s *ProxyServer) createTunnelConnection(destAddr string, destPort uint16) (uint32, error) {
	// 生成唯一的连接ID
	connID := s.generateConnID()

	// 组织连接请求消息
	request := append([]byte{msgTypeNewConn}, []byte(fmt.Sprintf("%s:%d", destAddr, destPort))...)

	// 通过隧道发送连接请求
	if err := s.tunnel.Write(request); err != nil {
		return 0, fmt.Errorf("通过隧道发送连接请求失败: %v", err)
	}

	// 存储连接
	s.activeConns.Store(connID, &Connection{
		id:         connID,
		targetConn: nil, // 在隧道响应后设置
	})

	log.Printf("创建隧道连接 ID: %d, 目标: %s:%d\n", connID, destAddr, destPort)

	return connID, nil
}

// handleTunnel 处理隧道连接
func (s *ProxyServer) handleTunnel(conn net.Conn) {
	defer conn.Close()

	// 设置连接超时
	conn.SetKeepAlive(true)
	conn.SetKeepAlivePeriod(30 * time.Second)
	conn.SetDeadline(time.Now().Add(5 * time.Minute))

	log.Printf("新的隧道连接已建立")
	tunnel := tunnel.NewTunnel(conn, s.encryptor)

	s.mutex.Lock()
	oldTunnel := s.tunnel
	s.tunnel = tunnel
	s.mutex.Unlock()

	// 优雅关闭旧隧道
	if oldTunnel != nil {
		go func() {
			time.Sleep(time.Second) // 等待旧连接处理完
			oldTunnel.Close()
		}()
	}

	// 通知隧道已就绪
	select {
	case <-s.tunnelReady:
		log.Printf("检测到已存在的隧道连接，关闭旧连接")
		return
	default:
		log.Printf("标记隧道为就绪状态")
		close(s.tunnelReady)
	}

	// 当隧道连接断开时，重置 tunnelReady 通道
	defer func() {
		s.mutex.Lock()
		s.tunnel = nil
		s.tunnelReady = make(chan struct{})
		s.mutex.Unlock()
		// 清理所有活跃连接
		s.activeConns.Range(func(key, value interface{}) bool {
			if conn, ok := value.(*Connection); ok && conn.targetConn != nil {
				conn.targetConn.Close()
			}
			s.activeConns.Delete(key)
			return true
		})
	}()

	for {
		data, err := tunnel.Read()
		if err != nil {
			log.Printf("隧道读取数据错误: %v\n", err)
			return
		}

		if len(data) == 0 {
			continue
		}

		switch data[0] {
		case msgTypeData:
			if len(data) < 5 {
				continue
			}
			connID := binary.BigEndian.Uint32(data[1:5])
			payload := data[5:]

			if conn, ok := s.activeConns.Load(connID); ok {
				activeConn := conn.(*Connection)
				if activeConn.targetConn != nil {
					// 使用带缓冲的写入
					select {
					case <-time.After(time.Second):
						log.Printf("[连接 %d] 写入超时", connID)
						s.cleanupConnection(connID)
					default:
						if _, err := activeConn.targetConn.Write(payload); err != nil {
							log.Printf("[连接 %d] 写入目标服务数据错误: %v\n", connID, err)
							s.cleanupConnection(connID)
						}
					}
				}
			}

		case msgTypeNewConn:
			// 处理客户端通过隧道发送的新连接响应
			if len(data) < 5 {
				log.Printf("无效的新连接响应: 数据太短\n")
				continue
			}
			connID := binary.BigEndian.Uint32(data[1:5])
			log.Printf("收到新连接响应，连接ID: %d\n", connID)

			if conn, ok := s.activeConns.Load(connID); ok {
				activeConn := conn.(*Connection)
				if activeConn.targetConn != nil {
					// 启动数据转发
					go func() {
						defer func() {
							s.activeConns.Delete(connID)
							activeConn.targetConn.Close()
						}()

						buf := s.bufferPool.Get().([]byte)
						defer s.bufferPool.Put(buf)

						for {
							s.mutex.RLock()
							currentTunnel := s.tunnel
							s.mutex.RUnlock()

							if currentTunnel == nil {
								log.Printf("[连接 %d] 隧道已断开\n", connID)
								return
							}

							n, err := activeConn.targetConn.Read(buf)
							if err != nil {
								log.Printf("[连接 %d] 读取SOCKS5连接数据错误: %v\n", connID, err)
								return
							}

							// 构造数据消息
							message := append([]byte{msgTypeData}, make([]byte, 4)...)
							binary.BigEndian.PutUint32(message[1:5], connID)
							message = append(message, buf[:n]...)

							if err := currentTunnel.Write(message); err != nil {
								log.Printf("[连接 %d] 发送数据到隧道错误: %v\n", connID, err)
								return
							}
						}
					}()
				}
			}

		default:
			log.Printf("未知的消息类型: %d\n", data[0])
		}
	}
}

// 添加一个新的方法来��理连接
func (s *ProxyServer) cleanupConnection(connID uint32) {
	if conn, ok := s.activeConns.Load(connID); ok {
		activeConn := conn.(*Connection)
		if activeConn.targetConn != nil {
			activeConn.targetConn.Close()
		}
		s.activeConns.Delete(connID)
		log.Printf("[连接 %d] 已清理\n", connID)
	}
}

// 添加一个方法来检查隧道是否就绪
func (s *ProxyServer) isTunnelReady() bool {
	select {
	case <-s.tunnelReady:
		return true
	default:
		return false
	}
}

// 添加新的数据转发方法
func (s *ProxyServer) forwardData(src, dst net.Conn, connID uint32) {
	buf := s.bufferPool.Get().([]byte)
	defer s.bufferPool.Put(buf)

	for {
		// 设置读取超时
		src.SetReadDeadline(time.Now().Add(2 * time.Minute))

		n, err := src.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("[连接 %d] 读取数据错误: %v", connID, err)
			}
			return
		}

		// 设置写入超时
		dst.SetWriteDeadline(time.Now().Add(30 * time.Second))

		if _, err := dst.Write(buf[:n]); err != nil {
			log.Printf("[连接 %d] 写入数据错误: %v", connID, err)
			return
		}
	}
}

// 添加健康检查方法
func (s *ProxyServer) startHealthCheck() {
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		for range ticker.C {
			s.activeConns.Range(func(key, value interface{}) bool {
				conn := value.(*Connection)
				if conn.lastActive.Add(5 * time.Minute).Before(time.Now()) {
					s.cleanupConnection(conn.id)
				}
				return true
			})
		}
	}()
}
