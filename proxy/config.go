package proxy

import (
	"fmt"
)

// NodeType 节点类型
type NodeType int

const (
	NodeTypeEntry NodeType = iota
	NodeTypeMiddle
	NodeTypeExit
)

// NodeConfig 节点配置
type NodeConfig struct {
	Type     NodeType // 节点类型
	Address  string   // 监听地址
	NextHops []string // 下一跳节点ID列表
}

// Config 代理配置
type Config struct {
	CurrentNode string                // 当前节点ID
	Nodes       map[string]NodeConfig // 节点配置，键为节点ID
}

// NewConfig 创建新的配置
func NewConfig() *Config {
	return &Config{
		Nodes: make(map[string]NodeConfig),
	}
}

// AddNode 添加节点配置
func (c *Config) AddNode(id string, nodeType NodeType, address string, nextHops []string) {
	c.Nodes[id] = NodeConfig{
		Type:     nodeType,
		Address:  address,
		NextHops: nextHops,
	}
}

// GetNode 获取节点配置
func (c *Config) GetNode(id string) (*NodeConfig, error) {
	if node, ok := c.Nodes[id]; ok {
		return &node, nil
	}
	return nil, fmt.Errorf("未找到节点配置: %s", id)
}

// Validate 验证配置
func (c *Config) Validate() error {
	if c.CurrentNode == "" {
		return fmt.Errorf("未设置当前节点ID")
	}

	if _, ok := c.Nodes[c.CurrentNode]; !ok {
		return fmt.Errorf("未找到当前节点配置: %s", c.CurrentNode)
	}

	for id, node := range c.Nodes {
		if node.Address == "" {
			return fmt.Errorf("节点 %s 未设置监听地址", id)
		}

		if node.Type == NodeTypeEntry || node.Type == NodeTypeMiddle {
			if len(node.NextHops) == 0 {
				return fmt.Errorf("节点 %s 未设置下一跳", id)
			}
			for _, nextHop := range node.NextHops {
				if _, ok := c.Nodes[nextHop]; !ok {
					return fmt.Errorf("节点 %s 的下一跳 %s 不存在", id, nextHop)
				}
			}
		}
	}

	return nil
}
