package server

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"reverseproxy/crypto"
	"reverseproxy/logger"
	"reverseproxy/tunnel"

	"github.com/xtaci/kcp-go"
)

// connection 表示一个活跃的连接
type connection struct {
	id         uint32
	localConn  net.Conn
	lastActive time.Time
}

// Server 服务器结构体
type Server struct {
	proxyAddr    string
	tunnelAddr   string
	protocol     string
	encryptor    crypto.Encryptor
	tunnel       *tunnel.Tunnel
	kcpConfig    *tunnel.KCPConfig
	done         chan struct{}
	activeConns  sync.Map
	nextConnID   uint32
	readTimeout  time.Duration
	writeTimeout time.Duration
	udpAddr      string
	udpConn      *net.UDPConn
}

// NewServer 创建新的服务器
func NewServer(proxyAddr, tunnelAddr string, key []byte, protocol string) (*Server, error) {
	encryptor, err := crypto.NewAESEncryptor(key)
	if err != nil {
		return nil, fmt.Errorf("创建加密器失败: %v", err)
	}

	return &Server{
		proxyAddr:    proxyAddr,
		tunnelAddr:   tunnelAddr,
		protocol:     protocol,
		encryptor:    encryptor,
		kcpConfig:    tunnel.DefaultKCPConfig(),
		done:         make(chan struct{}),
		readTimeout:  30 * time.Second,
		writeTimeout: 30 * time.Second,
	}, nil
}

// Start 启动服务器
func (s *Server) Start() error {
	// 启动隧道监听
	var tunnelListener net.Listener
	var err error
	if s.protocol == "kcp" {
		// 使用KCP协议
		kcpListener, err := kcp.ListenWithOptions(s.tunnelAddr, nil, 10, 3)
		if err != nil {
			return fmt.Errorf("启动KCP隧道监听失败: %v", err)
		}
		// 设置基础的KCP参数
		if err := kcpListener.SetDSCP(46); err != nil {
			logger.Warn("设置KCP DSCP失败: %v", err)
		}
		if err := kcpListener.SetReadBuffer(4194304); err != nil {
			logger.Warn("设置KCP读缓冲区失败: %v", err)
		}
		if err := kcpListener.SetWriteBuffer(4194304); err != nil {
			logger.Warn("设置KCP写缓冲区失败: %v", err)
		}
		tunnelListener = kcpListener
	} else {
		tunnelListener, err = net.Listen("tcp", s.tunnelAddr)
		if err != nil {
			return fmt.Errorf("启动TCP隧道监听失败: %v", err)
		}
	}
	defer tunnelListener.Close()

	// 等待隧道连接
	logger.Info("等待隧道连接...")
	conn, err := tunnelListener.Accept()
	if err != nil {
		return fmt.Errorf("接受隧道连接失败: %v", err)
	}

	// 如果是KCP连接，应用KCP配置
	if s.protocol == "kcp" {
		if kcpConn, ok := conn.(*kcp.UDPSession); ok {
			tunnel.ApplyKCPConfig(kcpConn, s.kcpConfig)
			logger.Debug("已应用KCP配置: MTU=%d, 窗口大小=%d/%d",
				s.kcpConfig.MTU, s.kcpConfig.SndWnd, s.kcpConfig.RcvWnd)
		}
	}

	// 创建隧道
	s.tunnel = tunnel.NewTunnel(conn, s.encryptor)

	// 执行隧道握手
	if err := s.tunnel.Handshake(true); err != nil {
		return fmt.Errorf("隧道握手失败: %v", err)
	}

	// 启动心跳检测
	go s.heartbeat()

	// 处理隧道消息
	go s.handleTunnelMessages()

	logger.Info("隧道已连接")

	// 启动SOCKS5代理监听
	proxyListener, err := net.Listen("tcp", s.proxyAddr)
	if err != nil {
		return fmt.Errorf("启动SOCKS5代理监听失败: %v", err)
	}
	defer proxyListener.Close()

	logger.Info("SOCKS5代理已启动: %s", s.proxyAddr)

	// 处理SOCKS5连接
	for {
		conn, err := proxyListener.Accept()
		if err != nil {
			logger.Error("接受SOCKS5连接失败: %v", err)
			continue
		}

		go s.handleSocks5Connection(conn)
	}
}

// handleSocks5Connection 处理SOCKS5连接
func (s *Server) handleSocks5Connection(conn net.Conn) {
	defer conn.Close()

	// 处理SOCKS5握手
	if err := s.handleSocks5Handshake(conn); err != nil {
		logger.Error("SOCKS5握手失败: %v", err)
		return
	}

	// 处理SOCKS5请求
	targetAddr, err := s.handleSocks5Request(conn)
	if err != nil {
		logger.Error("处理SOCKS5请求失败: %v", err)
		// 发送失败响应
		response := []byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0}
		conn.Write(response)
		return
	}

	// 生成连接ID
	connID := atomic.AddUint32(&s.nextConnID, 1)

	// 创建连接对象
	proxyConn := &connection{
		id:         connID,
		localConn:  conn,
		lastActive: time.Now(),
	}

	// 存储连接
	s.activeConns.Store(connID, proxyConn)
	defer s.cleanupConnection(connID)

	// 创建响应通道
	responseChan := make(chan error, 1)
	s.activeConns.Store(fmt.Sprintf("resp_%d", connID), responseChan)
	defer s.activeConns.Delete(fmt.Sprintf("resp_%d", connID))

	// 发送新连接请求给客户端
	request := make([]byte, 5+len(targetAddr))
	request[0] = 1 // 新连接请求
	binary.BigEndian.PutUint32(request[1:5], connID)
	copy(request[5:], []byte(targetAddr))

	if err := s.tunnel.Write(request); err != nil {
		logger.Error("发送新连接请求失败: %v", err)
		// 发送失败响应
		response := []byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0}
		conn.Write(response)
		return
	}

	// 等待客户端响应
	select {
	case err := <-responseChan:
		if err != nil {
			logger.Error("客户端连接失败: %v", err)
			// 发送失败响应
			response := []byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0}
			conn.Write(response)
			return
		}
	case <-time.After(s.readTimeout):
		logger.Error("等待客户端响应超时")
		// 发送失败响应
		response := []byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0}
		conn.Write(response)
		return
	}

	// 发送成功响应
	response := []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(response); err != nil {
		logger.Error("发送SOCKS5响应失败: %v", err)
		return
	}

	logger.Debug("新建连接 %d -> %s", connID, targetAddr)

	// 启动数据转发
	forwardErrChan := make(chan error, 1)
	go func() {
		forwardErrChan <- s.forwardData(proxyConn)
	}()

	// 等待转发结束或隧道关闭
	select {
	case <-s.done:
		return
	case err := <-forwardErrChan:
		if err != nil && err != io.EOF {
			logger.Error("数据转发失败: %v", err)
		}
	}
}

// handleSocks5Handshake 处理SOCKS5握手
func (s *Server) handleSocks5Handshake(conn net.Conn) error {
	// 读取版本和认证方法数量
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("读取SOCKS5握手失败: %v", err)
	}

	version := buf[0]
	if version != 5 {
		return fmt.Errorf("不支持的SOCKS版本: %d", version)
	}

	methodCount := int(buf[1])
	methods := make([]byte, methodCount)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("读取认证方法失败: %v", err)
	}

	// 回复使用无认证方法
	response := []byte{5, 0}
	if _, err := conn.Write(response); err != nil {
		return fmt.Errorf("发送认证响应失败: %v", err)
	}

	return nil
}

// handleSocks5Request 处理SOCKS5请求
func (s *Server) handleSocks5Request(conn net.Conn) (string, error) {
	// 读取请求头
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", fmt.Errorf("读取请求头失败: %v", err)
	}

	if header[0] != 5 {
		return "", fmt.Errorf("不支持的SOCKS版本: %d", header[0])
	}

	if header[2] != 0 {
		return "", fmt.Errorf("保留字节必须为0")
	}

	// 根据命令类型处理
	switch header[1] {
	case 1: // CONNECT
		return s.handleConnect(conn, header[3])
	case 3: // UDP ASSOCIATE
		return s.handleUDPAssociate(conn, header[3])
	default:
		return "", fmt.Errorf("不支持的命令类型: %d", header[1])
	}
}

// handleConnect 处理TCP CONNECT请求
func (s *Server) handleConnect(conn net.Conn, addrType byte) (string, error) {
	// 读取地址和端口
	return s.readAddress(conn, addrType)
}

// handleUDPAssociate 处理UDP ASSOCIATE请求
func (s *Server) handleUDPAssociate(conn net.Conn, addrType byte) (string, error) {
	// 读取客户端地址(这个地址在UDP转发中不使用)
	clientAddr, err := s.readAddress(conn, addrType)
	if err != nil {
		return "", err
	}

	// 如果UDP监听器还未创建，创建一个
	if s.udpConn == nil {
		// 解析代理地址获取IP
		host, _, err := net.SplitHostPort(s.proxyAddr)
		if err != nil {
			return "", fmt.Errorf("解析代理地址失败: %v", err)
		}

		// 在随机端口上创建UDP监听器
		addr, err := net.ResolveUDPAddr("udp", host+":0")
		if err != nil {
			return "", fmt.Errorf("解析UDP地址失败: %v", err)
		}

		udpConn, err := net.ListenUDP("udp", addr)
		if err != nil {
			return "", fmt.Errorf("创建UDP监听失败: %v", err)
		}

		s.udpConn = udpConn
		s.udpAddr = udpConn.LocalAddr().String()

		// 启动UDP处理协程
		go s.handleUDP()
	}

	logger.Debug("UDP ASSOCIATE 请求来自 %s, 分配UDP端口: %s", clientAddr, s.udpAddr)

	// 返回UDP监听地址
	host, port, err := net.SplitHostPort(s.udpAddr)
	if err != nil {
		return "", fmt.Errorf("解析UDP地址失败: %v", err)
	}

	portNum, err := strconv.Atoi(port)
	if err != nil {
		return "", fmt.Errorf("解析端口失败: %v", err)
	}

	// 发送响应
	response := make([]byte, 10)
	response[0] = 5 // VER
	response[1] = 0 // SUCCESS
	response[2] = 0 // RSV
	response[3] = 1 // IPv4

	// 写入IP地址
	ip := net.ParseIP(host).To4()
	copy(response[4:8], ip)

	// 写入端口
	binary.BigEndian.PutUint16(response[8:], uint16(portNum))

	if _, err := conn.Write(response); err != nil {
		return "", fmt.Errorf("发送UDP响应失败: %v", err)
	}

	return clientAddr, nil
}

// readAddress 读取SOCKS5地址
func (s *Server) readAddress(conn net.Conn, addrType byte) (string, error) {
	var addr string
	var port uint16

	switch addrType {
	case 1: // IPv4
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", fmt.Errorf("读取IPv4地址失败: %v", err)
		}
		addr = net.IP(buf).String()

	case 3: // 域名
		buf := make([]byte, 1)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", fmt.Errorf("读取域名长度失败: %v", err)
		}
		domainLen := int(buf[0])

		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", fmt.Errorf("读取域名失败: %v", err)
		}
		addr = string(domain)

	case 4: // IPv6
		buf := make([]byte, 16)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", fmt.Errorf("读取IPv6地址失败: %v", err)
		}
		addr = net.IP(buf).String()

	default:
		return "", fmt.Errorf("不支持的地址类型: %d", addrType)
	}

	// 读取端口
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return "", fmt.Errorf("读取端口失败: %v", err)
	}
	port = binary.BigEndian.Uint16(buf)

	return fmt.Sprintf("%s:%d", addr, port), nil
}

// handleUDP 处理UDP数据包
func (s *Server) handleUDP() {
	defer s.udpConn.Close()

	buffer := make([]byte, 64*1024)
	for {
		select {
		case <-s.done:
			return
		default:
			n, remoteAddr, err := s.udpConn.ReadFromUDP(buffer)
			if err != nil {
				logger.Error("读取UDP数据失败: %v", err)
				continue
			}

			// 解析SOCKS5 UDP请求头
			if n < 10 { // 最小UDP请求头长度
				continue
			}

			// SOCKS5 UDP请求头格式:
			// +----+------+------+----------+----------+----------+
			// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA  |
			// +----+------+------+----------+----------+----------+
			// | 2  |  1   |  1   | Variable |    2     | Variable|
			// +----+------+------+----------+----------+----------+

			frag := buffer[2] // 分片号
			if frag != 0 {
				// 暂不支持分片
				continue
			}

			addrType := buffer[3]
			var headerLen int
			var targetAddr string

			switch addrType {
			case 1: // IPv4
				if n < 10 {
					continue
				}
				ip := net.IP(buffer[4:8])
				port := binary.BigEndian.Uint16(buffer[8:10])
				targetAddr = fmt.Sprintf("%s:%d", ip.String(), port)
				headerLen = 10
			case 3: // 域名
				if n < 5 {
					continue
				}
				domainLen := int(buffer[4])
				if n < 5+domainLen+2 {
					continue
				}
				domain := string(buffer[5 : 5+domainLen])
				port := binary.BigEndian.Uint16(buffer[5+domainLen : 7+domainLen])
				targetAddr = fmt.Sprintf("%s:%d", domain, port)
				headerLen = 7 + domainLen
			case 4: // IPv6
				if n < 22 {
					continue
				}
				ip := net.IP(buffer[4:20])
				port := binary.BigEndian.Uint16(buffer[20:22])
				targetAddr = fmt.Sprintf("[%s]:%d", ip.String(), port)
				headerLen = 22
			default:
				continue
			}

			// 生成连接ID
			connID := atomic.AddUint32(&s.nextConnID, 1)

			// 准备转发数据
			data := make([]byte, n-headerLen+9)
			data[0] = 3 // UDP数据包
			binary.BigEndian.PutUint32(data[1:5], connID)
			// 写入源地址
			copy(data[5:], []byte(remoteAddr.String()))
			// 写入目标地址
			copy(data[5+len(remoteAddr.String()):], buffer[headerLen:n])

			// 发送到隧道
			if err := s.tunnel.Write(data); err != nil {
				logger.Error("发送UDP数据到隧道失败: %v", err)
				continue
			}

			logger.Debug("转发UDP数据包 %d -> %s", connID, targetAddr)
		}
	}
}

// heartbeat 发送心跳包
func (s *Server) heartbeat() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			if s.tunnel == nil {
				continue
			}

			// 发送心跳包
			heartbeat := []byte{0} // 0表示心跳包
			if err := s.tunnel.Write(heartbeat); err != nil {
				logger.Error("发送心跳包失败: %v", err)
				return
			}
		}
	}
}

// handleTunnelMessages 处理隧道消息
func (s *Server) handleTunnelMessages() {
	for {
		select {
		case <-s.done:
			return
		default:
			if s.tunnel == nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}

			// 读取消息
			data, err := s.tunnel.Read()
			if err != nil {
				logger.Error("读取隧道消息失败: %v", err)
				s.tunnel = nil
				return
			}

			if len(data) == 0 {
				continue
			}

			// 处理消息
			switch data[0] {
			case 0: // 心跳包
				continue
			case 1: // 新连接响应
				if err := s.handleConnectionResponse(data[1:]); err != nil {
					logger.Error("处理连接响应失败: %v", err)
				}
			case 2: // 数据转发
				if err := s.handleData(data[1:]); err != nil {
					logger.Error("处理数据转发失败: %v", err)
				}
			default:
				logger.Error("未知消息类型: %d", data[0])
			}
		}
	}
}

// handleConnectionResponse 处理连接响应
func (s *Server) handleConnectionResponse(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("连接响应数据长度不足")
	}

	// 解析连接ID
	connID := binary.BigEndian.Uint32(data[:4])

	// 获取响应通道
	respChanInterface, ok := s.activeConns.Load(fmt.Sprintf("resp_%d", connID))
	if !ok {
		return fmt.Errorf("未找到连接响应通道: %d", connID)
	}

	// 获取连接
	connInterface, ok := s.activeConns.Load(connID)
	if !ok {
		respChan := respChanInterface.(chan error)
		respChan <- fmt.Errorf("未找到连接: %d", connID)
		return fmt.Errorf("未找到连接: %d", connID)
	}

	conn := connInterface.(*connection)
	conn.lastActive = time.Now()

	// 发送响应
	respChan := respChanInterface.(chan error)
	respChan <- nil

	return nil
}

// handleData 处理数据转发
func (s *Server) handleData(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("数据长度不足")
	}

	// 解析连接ID
	connID := binary.BigEndian.Uint32(data[:4])
	payload := data[4:]

	// 获取连接
	connInterface, ok := s.activeConns.Load(connID)
	if !ok {
		return fmt.Errorf("未找到连接: %d", connID)
	}

	conn := connInterface.(*connection)
	conn.lastActive = time.Now()

	// 发送数据到本地连接
	if _, err := conn.localConn.Write(payload); err != nil {
		s.cleanupConnection(connID)
		return fmt.Errorf("发送数据到本地连接失败: %v", err)
	}

	return nil
}

// forwardData 转发本地连接的数据到隧道
func (s *Server) forwardData(conn *connection) error {
	buffer := make([]byte, 32*1024)
	for {
		select {
		case <-s.done:
			return nil
		default:
			// 读取本地连接数据
			n, err := conn.localConn.Read(buffer)
			if err != nil {
				if err == io.EOF {
					return err
				}
				if ne, ok := err.(net.Error); ok && ne.Temporary() {
					time.Sleep(100 * time.Millisecond)
					continue
				}
				return fmt.Errorf("读取本地连接数据失败: %v", err)
			}

			// 准备转发数据
			data := make([]byte, n+5)
			data[0] = 2 // 数据转发
			binary.BigEndian.PutUint32(data[1:5], conn.id)
			copy(data[5:], buffer[:n])

			// 发送数据到隧道
			if err := s.tunnel.Write(data); err != nil {
				return fmt.Errorf("发送数据到隧道失败: %v", err)
			}

			conn.lastActive = time.Now()
		}
	}
}

// cleanupConnection 清理连接
func (s *Server) cleanupConnection(connID uint32) {
	if conn, ok := s.activeConns.Load(connID); ok {
		activeConn := conn.(*connection)
		activeConn.localConn.Close()
		s.activeConns.Delete(connID)
		logger.Debug("清理连接 %d", connID)
	}
}

// Close 关闭服务器
func (s *Server) Close() error {
	close(s.done)

	// 关闭所有活跃连接
	s.activeConns.Range(func(key, value interface{}) bool {
		conn := value.(*connection)
		conn.localConn.Close()
		return true
	})

	// 关闭UDP监听器
	if s.udpConn != nil {
		s.udpConn.Close()
	}

	// 关闭隧道
	if s.tunnel != nil {
		return s.tunnel.Close()
	}

	return nil
}
