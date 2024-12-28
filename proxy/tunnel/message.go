package tunnel

import (
	"encoding/binary"
	"fmt"
)

// MessageType 消息类型
type MessageType byte

const (
	// 基础消息类型
	MessageTypeHeartbeat MessageType = iota
	MessageTypeData
	MessageTypeConnect
	MessageTypeConnectResponse
	MessageTypeDisconnect

	// 代理链路消息类型
	MessageTypeRouteRequest  // 路由请求
	MessageTypeRouteResponse // 路由响应
	MessageTypeRouteUpdate   // 路由更新
	MessageTypeRouteRemove   // 路由删除
)

// RouteFlags 路由标志
type RouteFlags byte

const (
	RouteFlagNone    RouteFlags = 0x00
	RouteFlagUrgent  RouteFlags = 0x01 // 紧急数据
	RouteFlagControl RouteFlags = 0x02 // 控制消息
)

// Header 消息头
type Header struct {
	Type       MessageType // 消息类型
	Flags      RouteFlags  // 路由标志
	ChainID    uint32      // 链路ID
	ConnID     uint32      // 连接ID
	TargetID   uint32      // 目标节点ID
	PayloadLen uint32      // 负载长度
}

// Message 完整消息
type Message struct {
	Header  Header // 消息头
	Payload []byte // 消息负载
}

// ParseHeader 解析消息头
func ParseHeader(data []byte) (*Header, error) {
	if len(data) < 18 { // 1 + 1 + 4 + 4 + 4 + 4
		return nil, fmt.Errorf("消息头长度不足")
	}

	header := &Header{
		Type:       MessageType(data[0]),
		Flags:      RouteFlags(data[1]),
		ChainID:    binary.BigEndian.Uint32(data[2:6]),
		ConnID:     binary.BigEndian.Uint32(data[6:10]),
		TargetID:   binary.BigEndian.Uint32(data[10:14]),
		PayloadLen: binary.BigEndian.Uint32(data[14:18]),
	}

	return header, nil
}

// EncodeHeader 编码消息头
func EncodeHeader(header *Header) []byte {
	data := make([]byte, 18)
	data[0] = byte(header.Type)
	data[1] = byte(header.Flags)
	binary.BigEndian.PutUint32(data[2:6], header.ChainID)
	binary.BigEndian.PutUint32(data[6:10], header.ConnID)
	binary.BigEndian.PutUint32(data[10:14], header.TargetID)
	binary.BigEndian.PutUint32(data[14:18], header.PayloadLen)
	return data
}

// ParseMessage 解析完整消息
func ParseMessage(data []byte) (*Message, error) {
	header, err := ParseHeader(data)
	if err != nil {
		return nil, err
	}

	if len(data) < 18+int(header.PayloadLen) {
		return nil, fmt.Errorf("消息负载长度不足")
	}

	message := &Message{
		Header:  *header,
		Payload: data[18 : 18+header.PayloadLen],
	}

	return message, nil
}

// EncodeMessage 编码完整消息
func EncodeMessage(message *Message) []byte {
	headerData := EncodeHeader(&message.Header)
	data := make([]byte, len(headerData)+len(message.Payload))
	copy(data, headerData)
	copy(data[len(headerData):], message.Payload)
	return data
}

// NewMessage 创建新消息
func NewMessage(msgType MessageType, flags RouteFlags, chainID, connID, targetID uint32, payload []byte) *Message {
	return &Message{
		Header: Header{
			Type:       msgType,
			Flags:      flags,
			ChainID:    chainID,
			ConnID:     connID,
			TargetID:   targetID,
			PayloadLen: uint32(len(payload)),
		},
		Payload: payload,
	}
}

// NewHeartbeatMessage 创建心跳消息
func NewHeartbeatMessage() *Message {
	return NewMessage(MessageTypeHeartbeat, RouteFlagNone, 0, 0, 0, nil)
}

// NewDataMessage 创建数据消息
func NewDataMessage(chainID, connID, targetID uint32, data []byte) *Message {
	return NewMessage(MessageTypeData, RouteFlagNone, chainID, connID, targetID, data)
}

// NewConnectMessage 创建连接请求消息
func NewConnectMessage(chainID, connID, targetID uint32, targetAddr string) *Message {
	return NewMessage(MessageTypeConnect, RouteFlagNone, chainID, connID, targetID, []byte(targetAddr))
}

// NewConnectResponseMessage 创建连接响应消息
func NewConnectResponseMessage(chainID, connID, targetID uint32, success bool) *Message {
	var status byte = 0
	if success {
		status = 1
	}
	return NewMessage(MessageTypeConnectResponse, RouteFlagNone, chainID, connID, targetID, []byte{status})
}

// NewDisconnectMessage 创建断开连接消息
func NewDisconnectMessage(chainID, connID, targetID uint32) *Message {
	return NewMessage(MessageTypeDisconnect, RouteFlagNone, chainID, connID, targetID, nil)
}

// NewRouteRequestMessage 创建路由请求消息
func NewRouteRequestMessage(chainID, targetID uint32) *Message {
	return NewMessage(MessageTypeRouteRequest, RouteFlagControl, chainID, 0, targetID, nil)
}

// NewRouteResponseMessage 创建路由响应消息
func NewRouteResponseMessage(chainID, targetID uint32, nextHop string) *Message {
	return NewMessage(MessageTypeRouteResponse, RouteFlagControl, chainID, 0, targetID, []byte(nextHop))
}

// NewRouteUpdateMessage 创建路由更新消息
func NewRouteUpdateMessage(chainID, targetID uint32, nextHop string) *Message {
	return NewMessage(MessageTypeRouteUpdate, RouteFlagControl, chainID, 0, targetID, []byte(nextHop))
}

// NewRouteRemoveMessage 创建路由删除消息
func NewRouteRemoveMessage(chainID, targetID uint32) *Message {
	return NewMessage(MessageTypeRouteRemove, RouteFlagControl, chainID, 0, targetID, nil)
}
