package proxy

import (
	"fmt"
	"sync"
	"time"
)

// Route 路由信息
type Route struct {
	ChainID    string    // 链路ID
	TargetID   string    // 目标节点ID
	NextHop    string    // 下一跳节点ID
	UpdateTime time.Time // 更新时间
}

// RouteManager 路由管理器
type RouteManager struct {
	config *Config
	routes sync.Map // map[string]*Route，键为"chainID:targetID"
	mu     sync.RWMutex
}

// NewRouteManager 创建新的路由管理器
func NewRouteManager(config *Config) *RouteManager {
	return &RouteManager{
		config: config,
		routes: sync.Map{},
	}
}

// AddRoute 添加路由
func (m *RouteManager) AddRoute(chainID, targetID, nextHop string) error {
	// 验证目标节点是否存在
	if _, err := m.config.GetNode(targetID); err != nil {
		return fmt.Errorf("目标节点不存在: %v", err)
	}

	// 验证下一跳节点是否存在
	if _, err := m.config.GetNode(nextHop); err != nil {
		return fmt.Errorf("下一跳节点不存在: %v", err)
	}

	// 创建路由
	route := &Route{
		ChainID:    chainID,
		TargetID:   targetID,
		NextHop:    nextHop,
		UpdateTime: time.Now(),
	}

	// 存储路由
	key := fmt.Sprintf("%s:%s", chainID, targetID)
	m.routes.Store(key, route)

	return nil
}

// GetNextHop 获取下一跳节点
func (m *RouteManager) GetNextHop(chainID, targetID string) (string, error) {
	// 查找路由
	key := fmt.Sprintf("%s:%s", chainID, targetID)
	routeInterface, ok := m.routes.Load(key)
	if !ok {
		return "", fmt.Errorf("未找到路由: %s", key)
	}
	route := routeInterface.(*Route)

	// 检查路由是否过期
	if time.Since(route.UpdateTime) > 5*time.Minute {
		m.routes.Delete(key)
		return "", fmt.Errorf("路由已过期: %s", key)
	}

	return route.NextHop, nil
}

// DeleteRoute 删除路由
func (m *RouteManager) DeleteRoute(chainID, targetID string) {
	key := fmt.Sprintf("%s:%s", chainID, targetID)
	m.routes.Delete(key)
}

// CleanExpiredRoutes 清理过期路由
func (m *RouteManager) CleanExpiredRoutes() {
	m.routes.Range(func(key, value interface{}) bool {
		route := value.(*Route)
		if time.Since(route.UpdateTime) > 5*time.Minute {
			m.routes.Delete(key)
		}
		return true
	})
}

// HasRoute 检查路由是否存在
func (m *RouteManager) HasRoute(chainID, targetID string) bool {
	key := fmt.Sprintf("%s:%s", chainID, targetID)
	_, ok := m.routes.Load(key)
	return ok
}

// UpdateRoute 更新路由
func (m *RouteManager) UpdateRoute(chainID, targetID, nextHop string) error {
	// 验证目标节点是否存在
	if _, err := m.config.GetNode(targetID); err != nil {
		return fmt.Errorf("目标节点不存在: %v", err)
	}

	// 验证下一跳节点是否存在
	if _, err := m.config.GetNode(nextHop); err != nil {
		return fmt.Errorf("下一跳节点不存在: %v", err)
	}

	// 更新路由
	key := fmt.Sprintf("%s:%s", chainID, targetID)
	if routeInterface, ok := m.routes.Load(key); ok {
		route := routeInterface.(*Route)
		route.NextHop = nextHop
		route.UpdateTime = time.Now()
		m.routes.Store(key, route)
	} else {
		// 如果路由不存在，创建新路由
		route := &Route{
			ChainID:    chainID,
			TargetID:   targetID,
			NextHop:    nextHop,
			UpdateTime: time.Now(),
		}
		m.routes.Store(key, route)
	}

	return nil
}
