package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Chain 代理链路
type Chain struct {
	ID        string    // 链路ID
	Nodes     []string  // 节点列表
	CreatedAt time.Time // 创建时间
}

// ChainManager 链路管理器
type ChainManager struct {
	chains sync.Map // map[string]*Chain，键为链路ID
	mu     sync.Mutex
}

// NewChainManager 创建新的链路管理器
func NewChainManager() *ChainManager {
	return &ChainManager{}
}

// CreateChain 创建新的链路
func (m *ChainManager) CreateChain(nodes []string) (*Chain, error) {
	// 生成链路ID
	id, err := generateChainID()
	if err != nil {
		return nil, fmt.Errorf("生成链路ID失败: %v", err)
	}

	// 创建链路
	chain := &Chain{
		ID:        id,
		Nodes:     nodes,
		CreatedAt: time.Now(),
	}

	// 存储链路
	m.chains.Store(id, chain)

	return chain, nil
}

// GetChain 获取链路
func (m *ChainManager) GetChain(id string) (*Chain, error) {
	if value, ok := m.chains.Load(id); ok {
		return value.(*Chain), nil
	}
	return nil, fmt.Errorf("未找到���路: %s", id)
}

// DeleteChain 删除链路
func (m *ChainManager) DeleteChain(id string) {
	m.chains.Delete(id)
}

// GetNextHop 获取下一跳节点
func (m *ChainManager) GetNextHop(chainID string, currentNode string) (string, error) {
	// 获取链路
	chain, err := m.GetChain(chainID)
	if err != nil {
		return "", err
	}

	// 查找当前节点在链路中的位置
	currentIndex := -1
	for i, node := range chain.Nodes {
		if node == currentNode {
			currentIndex = i
			break
		}
	}

	if currentIndex == -1 {
		return "", fmt.Errorf("当前节点不在链路中: %s", currentNode)
	}

	// 如果当前节点是最后一个节点，返回错误
	if currentIndex == len(chain.Nodes)-1 {
		return "", fmt.Errorf("当前节点是链路的最后一个节点")
	}

	// 返回下一个节点
	return chain.Nodes[currentIndex+1], nil
}

// GetPreviousHop 获取上一跳节点
func (m *ChainManager) GetPreviousHop(chainID string, currentNode string) (string, error) {
	// 获取链路
	chain, err := m.GetChain(chainID)
	if err != nil {
		return "", err
	}

	// 查找当前节点在链路中的位置
	currentIndex := -1
	for i, node := range chain.Nodes {
		if node == currentNode {
			currentIndex = i
			break
		}
	}

	if currentIndex == -1 {
		return "", fmt.Errorf("当前节点不在链路中: %s", currentNode)
	}

	// 如果当前节点是第一个节点，返回错误
	if currentIndex == 0 {
		return "", fmt.Errorf("当前节点是链路的第一个节点")
	}

	// 返回上一个节点
	return chain.Nodes[currentIndex-1], nil
}

// IsNodeInChain 检查节点是否在链路中
func (m *ChainManager) IsNodeInChain(chainID string, nodeID string) bool {
	chain, err := m.GetChain(chainID)
	if err != nil {
		return false
	}

	for _, node := range chain.Nodes {
		if node == nodeID {
			return true
		}
	}

	return false
}

// CleanupExpiredChains 清理过期的链路
func (m *ChainManager) CleanupExpiredChains(maxAge time.Duration) {
	m.chains.Range(func(key, value interface{}) bool {
		chain := value.(*Chain)
		if time.Since(chain.CreatedAt) > maxAge {
			m.chains.Delete(key)
		}
		return true
	})
}

// generateChainID 生成链路ID
func generateChainID() (string, error) {
	// 生成16字节的随机数
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	// 转换为十六进制字符串
	return hex.EncodeToString(bytes), nil
}
