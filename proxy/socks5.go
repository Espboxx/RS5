package proxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const (
	// SOCKS5 version
	socks5Version = 0x05

	// Authentication methods
	authNone         = 0x00
	authGSSAPI       = 0x01
	authPassword     = 0x02
	authNoAcceptable = 0xFF

	// Commands
	cmdConnect      = 0x01
	cmdBind         = 0x02
	cmdUDPAssociate = 0x03

	// Address types
	addrTypeIPv4   = 0x01
	addrTypeDomain = 0x03
	addrTypeIPv6   = 0x04

	// Response codes
	respSuccess                 = 0x00
	respServerFailure           = 0x01
	respNotAllowed              = 0x02
	respNetworkUnreachable      = 0x03
	respHostUnreachable         = 0x04
	respConnectionRefused       = 0x05
	respTTLExpired              = 0x06
	respCommandNotSupported     = 0x07
	respAddressTypeNotSupported = 0x08
)

// SOCKS5Handler SOCKS5协议处理器
type SOCKS5Handler struct {
	conn net.Conn
}

// NewSOCKS5Handler 创建新的SOCKS5处理器
func NewSOCKS5Handler(conn net.Conn) *SOCKS5Handler {
	return &SOCKS5Handler{
		conn: conn,
	}
}

// Handshake 执行SOCKS5握手
func (h *SOCKS5Handler) Handshake() error {
	// 读取版本和认证方法数量
	buf := make([]byte, 2)
	if _, err := io.ReadFull(h.conn, buf); err != nil {
		return fmt.Errorf("读取版本和认证方法数量失败: %v", err)
	}

	version := buf[0]
	if version != socks5Version {
		return fmt.Errorf("不支持的SOCKS版本: %d", version)
	}

	methodCount := int(buf[1])
	methods := make([]byte, methodCount)
	if _, err := io.ReadFull(h.conn, methods); err != nil {
		return fmt.Errorf("读取认证方法失败: %v", err)
	}

	// 目前只支持无认证方式
	hasNoAuth := false
	for _, method := range methods {
		if method == authNone {
			hasNoAuth = true
			break
		}
	}

	if !hasNoAuth {
		// 发送不支持的认证方法响应
		h.conn.Write([]byte{socks5Version, authNoAcceptable})
		return fmt.Errorf("不支持的认证方法")
	}

	// 发送无认证方式响应
	if _, err := h.conn.Write([]byte{socks5Version, authNone}); err != nil {
		return fmt.Errorf("发送认证响应失败: %v", err)
	}

	return nil
}

// ReadRequest 读取SOCKS5请求
func (h *SOCKS5Handler) ReadRequest() (byte, string, error) {
	// 读取版本、命令、保留字节和地址类型
	buf := make([]byte, 4)
	if _, err := io.ReadFull(h.conn, buf); err != nil {
		return 0, "", fmt.Errorf("读取请求头失败: %v", err)
	}

	version := buf[0]
	if version != socks5Version {
		return 0, "", fmt.Errorf("不支持的SOCKS版本: %d", version)
	}

	cmd := buf[1]
	addrType := buf[3]

	// 读取目标地址
	var addr string
	switch addrType {
	case addrTypeIPv4:
		// 读取IPv4地址
		buf = make([]byte, 4)
		if _, err := io.ReadFull(h.conn, buf); err != nil {
			return 0, "", fmt.Errorf("读取IPv4地址失败: %v", err)
		}
		addr = net.IP(buf).String()

	case addrTypeDomain:
		// 读取域名长度
		buf = make([]byte, 1)
		if _, err := io.ReadFull(h.conn, buf); err != nil {
			return 0, "", fmt.Errorf("读取域名长度失败: %v", err)
		}
		domainLen := int(buf[0])

		// 读取域名
		buf = make([]byte, domainLen)
		if _, err := io.ReadFull(h.conn, buf); err != nil {
			return 0, "", fmt.Errorf("读取域名失败: %v", err)
		}
		addr = string(buf)

	case addrTypeIPv6:
		// 读取IPv6地址
		buf = make([]byte, 16)
		if _, err := io.ReadFull(h.conn, buf); err != nil {
			return 0, "", fmt.Errorf("读取IPv6地址失败: %v", err)
		}
		addr = net.IP(buf).String()

	default:
		return 0, "", fmt.Errorf("不支持的地址类型: %d", addrType)
	}

	// 读取端口
	buf = make([]byte, 2)
	if _, err := io.ReadFull(h.conn, buf); err != nil {
		return 0, "", fmt.Errorf("读取端口失败: %v", err)
	}
	port := binary.BigEndian.Uint16(buf)

	// 组合地址和端口
	targetAddr := fmt.Sprintf("%s:%d", addr, port)

	return cmd, targetAddr, nil
}

// SendResponse 发送SOCKS5响应
func (h *SOCKS5Handler) SendResponse(code byte, targetAddr string) error {
	// 解析目标地址
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return fmt.Errorf("解析目标地址失败: %v", err)
	}

	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return fmt.Errorf("解析端口失败: %v", err)
	}

	// 构建响应
	response := make([]byte, 0, 10)
	response = append(response, socks5Version, code, 0x00) // 版本、响应码、保留字节

	// 添加地址
	ip := net.ParseIP(host)
	if ip == nil {
		// 域名
		response = append(response, addrTypeDomain)
		response = append(response, byte(len(host)))
		response = append(response, []byte(host)...)
	} else if ip.To4() != nil {
		// IPv4
		response = append(response, addrTypeIPv4)
		response = append(response, ip.To4()...)
	} else {
		// IPv6
		response = append(response, addrTypeIPv6)
		response = append(response, ip.To16()...)
	}

	// 添加端口
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	response = append(response, portBytes...)

	// 发送响应
	if _, err := h.conn.Write(response); err != nil {
		return fmt.Errorf("发送响应失败: %v", err)
	}

	return nil
}
