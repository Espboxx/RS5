package proxy

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"reverseproxy/logger"
	"reverseproxy/proxy/tunnel"
)

// Node 代理节点
type Node struct {
	config       *Config
	routeManager *RouteManager
	tunnels      sync.Map // map[string]*tunnel.Tunnel，键为节点ID
	connections  sync.Map // map[uint32]*Connection，键为连接ID
	nextConnID   uint32
	done         chan struct{}
}

// Connection 连接信息
type Connection struct {
	ID         uint32
	LocalConn  net.Conn
	ChainID    string
	TargetID   string
	TargetAddr string
	LastActive time.Time
}

// NewNode 创建新的代理节点
func NewNode(config *Config) (*Node, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("配置验证失败: %v", err)
	}

	return &Node{
		config:       config,
		routeManager: NewRouteManager(config),
		tunnels:      sync.Map{},
		connections:  sync.Map{},
		nextConnID:   0,
		done:         make(chan struct{}),
	}, nil
}

// Start 启动节点
func (n *Node) Start() error {
	// 获取当前节点配置
	currentNode, err := n.config.GetNode(n.config.CurrentNode)
	if err != nil {
		return fmt.Errorf("获取当前节点配置失败: %v", err)
	}

	// 根据节点类型启动不同的服务
	switch currentNode.Type {
	case NodeTypeEntry:
		return n.startEntryNode()
	case NodeTypeMiddle:
		return n.startMiddleNode()
	case NodeTypeExit:
		return n.startExitNode()
	default:
		return fmt.Errorf("不支持的节点类型: %d", currentNode.Type)
	}
}

// startEntryNode 启动入口节点
func (n *Node) startEntryNode() error {
	// 启动SOCKS5监听
	currentNode, _ := n.config.GetNode(n.config.CurrentNode)
	listener, err := net.Listen("tcp", currentNode.Address)
	if err != nil {
		return fmt.Errorf("启动监听失败: %v", err)
	}
	defer listener.Close()

	logger.Info("入口节点已启动，监听地址: %s", currentNode.Address)

	// 连接到下一跳节点
	for _, nextHop := range currentNode.NextHops {
		go n.connectToNode(nextHop)
	}

	// 处理入站连接
	for {
		select {
		case <-n.done:
			return nil
		default:
			conn, err := listener.Accept()
			if err != nil {
				logger.Error("接受连接失败: %v", err)
				continue
			}
			go n.handleInboundConnection(conn)
		}
	}
}

// startMiddleNode 启动中间节点
func (n *Node) startMiddleNode() error {
	// 启动监听
	currentNode, _ := n.config.GetNode(n.config.CurrentNode)
	listener, err := net.Listen("tcp", currentNode.Address)
	if err != nil {
		return fmt.Errorf("启动监听失败: %v", err)
	}
	defer listener.Close()

	logger.Info("中间节点已启动，监听地址: %s", currentNode.Address)

	// 连接到下一跳节点
	for _, nextHop := range currentNode.NextHops {
		go n.connectToNode(nextHop)
	}

	// 处理入站连接
	for {
		select {
		case <-n.done:
			return nil
		default:
			conn, err := listener.Accept()
			if err != nil {
				logger.Error("接受连接失败: %v", err)
				continue
			}
			go n.handleNodeConnection(conn)
		}
	}
}

// startExitNode 启动出口节点
func (n *Node) startExitNode() error {
	// 启动监听
	currentNode, _ := n.config.GetNode(n.config.CurrentNode)
	listener, err := net.Listen("tcp", currentNode.Address)
	if err != nil {
		return fmt.Errorf("启动监听失败: %v", err)
	}
	defer listener.Close()

	logger.Info("出口节点已启��，监听地址: %s", currentNode.Address)

	// 处理入站连接
	for {
		select {
		case <-n.done:
			return nil
		default:
			conn, err := listener.Accept()
			if err != nil {
				logger.Error("接受连接失败: %v", err)
				continue
			}
			go n.handleNodeConnection(conn)
		}
	}
}

// connectToNode 连接到其他节点
func (n *Node) connectToNode(nodeID string) {
	for {
		select {
		case <-n.done:
			return
		default:
			node, err := n.config.GetNode(nodeID)
			if err != nil {
				logger.Error("获取节点配置失败: %v", err)
				time.Sleep(5 * time.Second)
				continue
			}

			// 建立连接
			conn, err := net.Dial("tcp", node.Address)
			if err != nil {
				logger.Error("连接节点失败: %v", err)
				time.Sleep(5 * time.Second)
				continue
			}

			// 创建隧道
			tun := tunnel.NewTunnel(conn, nil) // TODO: 实现加密器
			if err := tun.Handshake(false); err != nil {
				logger.Error("隧道握手失败: %v", err)
				conn.Close()
				time.Sleep(5 * time.Second)
				continue
			}

			// 存储隧道
			n.tunnels.Store(nodeID, tun)
			logger.Info("已连接到节点: %s", nodeID)

			// 处理隧道消息
			n.handleTunnel(nodeID, tun)

			// 隧道断开后重新连接
			n.tunnels.Delete(nodeID)
			logger.Info("与节点的连接断开，准备重连: %s", nodeID)
			time.Sleep(5 * time.Second)
		}
	}
}

// handleNodeConnection 处理节点间连接
func (n *Node) handleNodeConnection(conn net.Conn) {
	defer conn.Close()

	// 创建隧道
	tun := tunnel.NewTunnel(conn, nil) // TODO: 实现加密器
	if err := tun.Handshake(true); err != nil {
		logger.Error("隧道握手失败: %v", err)
		return
	}

	// 等待并处理第一个消息以确定对端节点ID
	msg, err := tun.ReadMessage()
	if err != nil {
		logger.Error("读取消息失败: %v", err)
		return
	}

	// 验证消息类型和节点ID
	if msg.Header.Type != tunnel.MessageTypeRouteRequest {
		logger.Error("无效的首个消息类型")
		return
	}

	nodeID := string(msg.Payload)
	if _, ok := n.config.Nodes[nodeID]; !ok {
		logger.Error("未知的节点ID: %s", nodeID)
		return
	}

	// 存储隧道
	n.tunnels.Store(nodeID, tun)
	logger.Info("接受节点连接: %s", nodeID)

	// 处理隧道消息
	n.handleTunnel(nodeID, tun)

	// 清理隧道
	n.tunnels.Delete(nodeID)
}

// handleInboundConnection 处理入站SOCKS5连接
func (n *Node) handleInboundConnection(conn net.Conn) {
	defer conn.Close()

	// 创建SOCKS5处理器
	handler := NewSOCKS5Handler(conn)

	// 执行SOCKS5握手
	if err := handler.Handshake(); err != nil {
		logger.Error("SOCKS5握手失败: %v", err)
		return
	}

	// 读取SOCKS5请求
	cmd, targetAddr, err := handler.ReadRequest()
	if err != nil {
		logger.Error("读取SOCKS5请求失败: %v", err)
		return
	}

	// 根据命令类型处理请求
	switch cmd {
	case cmdConnect:
		if err := n.handleConnect(handler, targetAddr); err != nil {
			logger.Error("处理CONNECT请求失败: %v", err)
			handler.SendResponse(respServerFailure, targetAddr)
		}
	case cmdBind:
		logger.Error("不支持BIND命令")
		handler.SendResponse(respCommandNotSupported, targetAddr)
	case cmdUDPAssociate:
		logger.Error("不支持UDP ASSOCIATE命令")
		handler.SendResponse(respCommandNotSupported, targetAddr)
	default:
		logger.Error("不支持的命令类型: %d", cmd)
		handler.SendResponse(respCommandNotSupported, targetAddr)
	}
}

// handleTunnel 处理隧道消息
func (n *Node) handleTunnel(nodeID string, tun *tunnel.Tunnel) {
	for {
		msg, err := tun.ReadMessage()
		if err != nil {
			logger.Error("读取隧道消息失败: %v", err)
			return
		}

		switch msg.Header.Type {
		case tunnel.MessageTypeHeartbeat:
			// 响应���跳
			response := tunnel.NewHeartbeatMessage()
			if err := tun.WriteMessage(response); err != nil {
				logger.Error("发送心跳响应失败: %v", err)
				return
			}

		case tunnel.MessageTypeData:
			// 处理数据转发
			if err := n.handleDataMessage(msg); err != nil {
				logger.Error("处理数据消息失败: %v", err)
			}

		case tunnel.MessageTypeConnect:
			// 处理连接请求
			if err := n.handleConnectMessage(msg); err != nil {
				logger.Error("处理连接请求失败: %v", err)
			}

		case tunnel.MessageTypeConnectResponse:
			// 处理连接响应
			if err := n.handleConnectResponseMessage(msg); err != nil {
				logger.Error("处理连接响应失败: %v", err)
			}

		case tunnel.MessageTypeDisconnect:
			// 处理断开连接请求
			if err := n.handleDisconnectMessage(msg); err != nil {
				logger.Error("处理断开连接请求失败: %v", err)
			}

		case tunnel.MessageTypeRouteRequest:
			// 处理路由请求
			if err := n.handleRouteRequestMessage(msg); err != nil {
				logger.Error("处理路由请求失败: %v", err)
			}

		case tunnel.MessageTypeRouteResponse:
			// 处理路由响应
			if err := n.handleRouteResponseMessage(msg); err != nil {
				logger.Error("处理路由响应失败: %v", err)
			}

		default:
			logger.Error("未知的消息类型: %d", msg.Header.Type)
		}
	}
}

// handleDataMessage 处理数据消息
func (n *Node) handleDataMessage(msg *tunnel.Message) error {
	// 获取连接
	connInterface, ok := n.connections.Load(msg.Header.ConnID)
	if !ok {
		return fmt.Errorf("未找到连接: %d", msg.Header.ConnID)
	}
	conn := connInterface.(*Connection)

	// 检查是否是目标节点
	if n.config.CurrentNode == conn.TargetID {
		// 发送数据到本地连接
		if _, err := conn.LocalConn.Write(msg.Payload); err != nil {
			return fmt.Errorf("发送数据到本地连接失败: %v", err)
		}
	} else {
		// 转发到下一跳
		nextHop, err := n.routeManager.GetNextHop(conn.ChainID, conn.TargetID)
		if err != nil {
			return fmt.Errorf("获取下一跳失败: %v", err)
		}

		tunInterface, ok := n.tunnels.Load(nextHop)
		if !ok {
			return fmt.Errorf("未找到到下一跳的隧道: %s", nextHop)
		}
		tun := tunInterface.(*tunnel.Tunnel)

		if err := tun.WriteMessage(msg); err != nil {
			return fmt.Errorf("转发数据失败: %v", err)
		}
	}

	return nil
}

// handleConnect 处理CONNECT请求
func (n *Node) handleConnect(handler *SOCKS5Handler, targetAddr string) error {
	// 生成连接ID
	connID := atomic.AddUint32(&n.nextConnID, 1)

	// 选择代理链路
	chainID := "chain-1"     // TODO: 实现链路选择
	targetNodeID := "exit-1" // TODO: 实现目标节点选择

	// 创建连接对象
	connection := &Connection{
		ID:         connID,
		LocalConn:  handler.conn,
		ChainID:    chainID,
		TargetID:   targetNodeID,
		TargetAddr: targetAddr,
		LastActive: time.Now(),
	}

	// 存储连接
	n.connections.Store(connID, connection)

	// 获取下一跳
	nextHop, err := n.routeManager.GetNextHop(chainID, targetNodeID)
	if err != nil {
		n.connections.Delete(connID)
		return fmt.Errorf("获取下一跳失败: %v", err)
	}

	// 获取隧道
	tunInterface, ok := n.tunnels.Load(nextHop)
	if !ok {
		n.connections.Delete(connID)
		return fmt.Errorf("未找到到下一跳的隧道: %s", nextHop)
	}
	tun := tunInterface.(*tunnel.Tunnel)

	// 将字符串ID转换为uint32
	chainIDInt, _ := strconv.ParseUint(chainID[6:], 10, 32)       // chain-1 -> 1
	targetIDInt, _ := strconv.ParseUint(targetNodeID[5:], 10, 32) // exit-1 -> 1

	// 发送连接请求
	msg := tunnel.NewConnectMessage(uint32(chainIDInt), connID, uint32(targetIDInt), targetAddr)
	if err := tun.WriteMessage(msg); err != nil {
		n.connections.Delete(connID)
		return fmt.Errorf("发送连接请求失败: %v", err)
	}

	// 发送成功响应
	if err := handler.SendResponse(respSuccess, targetAddr); err != nil {
		n.connections.Delete(connID)
		return fmt.Errorf("发送响应失败: %v", err)
	}

	// 启动数据转发
	go n.forwardLocalData(connection)

	return nil
}

// handleConnectMessage 处理连接请求消息
func (n *Node) handleConnectMessage(msg *tunnel.Message) error {
	// 检查是否是目标节点
	targetID := strconv.FormatUint(uint64(msg.Header.TargetID), 10)
	if targetID != n.config.CurrentNode {
		// 不是目标节点，转发到下一跳
		nextHop, err := n.routeManager.GetNextHop(strconv.FormatUint(uint64(msg.Header.ChainID), 10), targetID)
		if err != nil {
			return fmt.Errorf("获取下一跳失败: %v", err)
		}

		tunInterface, ok := n.tunnels.Load(nextHop)
		if !ok {
			return fmt.Errorf("未找到到下一跳的隧道: %s", nextHop)
		}
		tun := tunInterface.(*tunnel.Tunnel)

		if err := tun.WriteMessage(msg); err != nil {
			return fmt.Errorf("转发连接请求失败: %v", err)
		}
		return nil
	}

	// 是目标节点，建立到目标地址的连接
	targetAddr := string(msg.Payload)
	conn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		// 连接失败，发送失败响应
		response := tunnel.NewConnectResponseMessage(msg.Header.ChainID, msg.Header.ConnID, msg.Header.TargetID, false)
		if tunInterface, ok := n.tunnels.Load(msg.Header.TargetID); ok {
			if err := tunInterface.(*tunnel.Tunnel).WriteMessage(response); err != nil {
				return fmt.Errorf("发送连接失败响应失败: %v", err)
			}
		}
		return fmt.Errorf("连接目标地址失败: %v", err)
	}

	// 创建连接对象
	connection := &Connection{
		ID:         msg.Header.ConnID,
		LocalConn:  conn,
		ChainID:    strconv.FormatUint(uint64(msg.Header.ChainID), 10),
		TargetID:   targetID,
		TargetAddr: targetAddr,
		LastActive: time.Now(),
	}

	// 存储连接
	n.connections.Store(msg.Header.ConnID, connection)

	// 发送成功响应
	response := tunnel.NewConnectResponseMessage(msg.Header.ChainID, msg.Header.ConnID, msg.Header.TargetID, true)
	if tunInterface, ok := n.tunnels.Load(msg.Header.TargetID); ok {
		if err := tunInterface.(*tunnel.Tunnel).WriteMessage(response); err != nil {
			n.connections.Delete(msg.Header.ConnID)
			conn.Close()
			return fmt.Errorf("发送连接成功响应失败: %v", err)
		}
	}

	// 启动数据转发
	go n.forwardLocalData(connection)

	return nil
}

// handleConnectResponseMessage 处理连接响应消息
func (n *Node) handleConnectResponseMessage(msg *tunnel.Message) error {
	// 检查是否是目标节点
	targetID := strconv.FormatUint(uint64(msg.Header.TargetID), 10)
	if targetID != n.config.CurrentNode {
		// 不是目标节点，转发到下一跳
		nextHop, err := n.routeManager.GetNextHop(strconv.FormatUint(uint64(msg.Header.ChainID), 10), targetID)
		if err != nil {
			return fmt.Errorf("获取下一跳失败: %v", err)
		}

		tunInterface, ok := n.tunnels.Load(nextHop)
		if !ok {
			return fmt.Errorf("未找到��下一跳的隧道: %s", nextHop)
		}
		tun := tunInterface.(*tunnel.Tunnel)

		if err := tun.WriteMessage(msg); err != nil {
			return fmt.Errorf("转发连接响应失败: %v", err)
		}
		return nil
	}

	// 获取连接
	connInterface, ok := n.connections.Load(msg.Header.ConnID)
	if !ok {
		return fmt.Errorf("未找到连接: %d", msg.Header.ConnID)
	}
	conn := connInterface.(*Connection)

	// 检查连接是否成功
	success := msg.Payload[0] == 1
	if !success {
		// 连接失败，清理连接
		n.connections.Delete(msg.Header.ConnID)
		conn.LocalConn.Close()
		return fmt.Errorf("目标连接失败")
	}

	return nil
}

// handleDisconnectMessage 处理断开连接消息
func (n *Node) handleDisconnectMessage(msg *tunnel.Message) error {
	// 检查是否是目标节点
	targetID := strconv.FormatUint(uint64(msg.Header.TargetID), 10)
	if targetID != n.config.CurrentNode {
		// 不是目标节点，转发到下一跳
		nextHop, err := n.routeManager.GetNextHop(strconv.FormatUint(uint64(msg.Header.ChainID), 10), targetID)
		if err != nil {
			return fmt.Errorf("获取下一跳失败: %v", err)
		}

		tunInterface, ok := n.tunnels.Load(nextHop)
		if !ok {
			return fmt.Errorf("未找到到下一跳的隧道: %s", nextHop)
		}
		tun := tunInterface.(*tunnel.Tunnel)

		if err := tun.WriteMessage(msg); err != nil {
			return fmt.Errorf("转发断开连接请求失败: %v", err)
		}
		return nil
	}

	// 获取连接
	if connInterface, ok := n.connections.Load(msg.Header.ConnID); ok {
		conn := connInterface.(*Connection)
		conn.LocalConn.Close()
		n.connections.Delete(msg.Header.ConnID)
	}

	return nil
}

// handleRouteRequestMessage 处理路由请求消息
func (n *Node) handleRouteRequestMessage(msg *tunnel.Message) error {
	// 获取请求节点ID
	nodeID := string(msg.Payload)

	// 检查节点是否存在
	if _, ok := n.config.Nodes[nodeID]; !ok {
		// 发送失败响应
		response := tunnel.NewRouteResponseMessage(msg.Header.ChainID, msg.Header.ConnID, msg.Header.TargetID, false)
		if tunInterface, ok := n.tunnels.Load(msg.Header.TargetID); ok {
			if err := tunInterface.(*tunnel.Tunnel).WriteMessage(response); err != nil {
				return fmt.Errorf("发送路由失败响应失败: %v", err)
			}
		}
		return fmt.Errorf("未知的节点ID: %s", nodeID)
	}

	// 添加路由
	if err := n.routeManager.AddRoute(strconv.FormatUint(uint64(msg.Header.ChainID), 10), nodeID, msg.Header.TargetID); err != nil {
		// 发送失败响应
		response := tunnel.NewRouteResponseMessage(msg.Header.ChainID, msg.Header.ConnID, msg.Header.TargetID, false)
		if tunInterface, ok := n.tunnels.Load(msg.Header.TargetID); ok {
			if err := tunInterface.(*tunnel.Tunnel).WriteMessage(response); err != nil {
				return fmt.Errorf("发送路由失败响应失败: %v", err)
			}
		}
		return fmt.Errorf("添加路由失败: %v", err)
	}

	// 发送成功响应
	response := tunnel.NewRouteResponseMessage(msg.Header.ChainID, msg.Header.ConnID, msg.Header.TargetID, true)
	if tunInterface, ok := n.tunnels.Load(msg.Header.TargetID); ok {
		if err := tunInterface.(*tunnel.Tunnel).WriteMessage(response); err != nil {
			return fmt.Errorf("发送路由成功响应失败: %v", err)
		}
	}

	return nil
}

// handleRouteResponseMessage 处理路由响应消息
func (n *Node) handleRouteResponseMessage(msg *tunnel.Message) error {
	// 检查是否是目标节点
	targetID := strconv.FormatUint(uint64(msg.Header.TargetID), 10)
	if targetID != n.config.CurrentNode {
		// 不是目标节点，转发到下一跳
		nextHop, err := n.routeManager.GetNextHop(strconv.FormatUint(uint64(msg.Header.ChainID), 10), targetID)
		if err != nil {
			return fmt.Errorf("获取下一跳失败: %v", err)
		}

		tunInterface, ok := n.tunnels.Load(nextHop)
		if !ok {
			return fmt.Errorf("未找到到下一跳的隧道: %s", nextHop)
		}
		tun := tunInterface.(*tunnel.Tunnel)

		if err := tun.WriteMessage(msg); err != nil {
			return fmt.Errorf("转发路由响应失败: %v", err)
		}
		return nil
	}

	// 检查路由是否成功
	success := msg.Payload[0] == 1
	if !success {
		return fmt.Errorf("路由请求失败")
	}

	return nil
}

// Close 关闭节点
func (n *Node) Close() error {
	close(n.done)

	// 关闭所有隧道
	n.tunnels.Range(func(key, value interface{}) bool {
		tun := value.(*tunnel.Tunnel)
		tun.Close()
		return true
	})

	// 关闭所有连接
	n.connections.Range(func(key, value interface{}) bool {
		conn := value.(*Connection)
		conn.LocalConn.Close()
		return true
	})

	return nil
}

// forwardLocalData 转发本地连接数据
func (n *Node) forwardLocalData(conn *Connection) {
	defer func() {
		conn.LocalConn.Close()
		n.connections.Delete(conn.ID)
	}()

	buffer := make([]byte, 32*1024)
	for {
		// 读取本地连接数据
		readN, err := conn.LocalConn.Read(buffer)
		if err != nil {
			if err != io.EOF {
				logger.Error("读取本地连接数据失败: %v", err)
			}
			return
		}

		// 获取下一跳
		nextHop, err := n.routeManager.GetNextHop(conn.ChainID, conn.TargetID)
		if err != nil {
			logger.Error("获取下一跳失败: %v", err)
			return
		}

		// 获取隧道
		tunInterface, ok := n.tunnels.Load(nextHop)
		if !ok {
			logger.Error("未找到到下一跳的隧道: %s", nextHop)
			return
		}
		tun := tunInterface.(*tunnel.Tunnel)

		// 将字符串ID转换为uint32
		chainIDInt, _ := strconv.ParseUint(conn.ChainID[6:], 10, 32)   // chain-1 -> 1
		targetIDInt, _ := strconv.ParseUint(conn.TargetID[5:], 10, 32) // exit-1 -> 1

		// 创建数据消息
		msg := tunnel.NewDataMessage(uint32(chainIDInt), conn.ID, uint32(targetIDInt), buffer[:readN])

		// 发送数据
		if err := tun.WriteMessage(msg); err != nil {
			logger.Error("发送数据失败: %v", err)
			return
		}

		// 更新活动时间
		conn.LastActive = time.Now()
	}
}
