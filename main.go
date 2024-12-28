package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"reverseproxy/client"
	"reverseproxy/logger"
	"reverseproxy/server"
)

func main() {
	// 初始化日志系统
	logConfig := logger.Config{
		Level:        "info",
		ToFile:       false,
		FilePath:     filepath.Join("logs", "reverseproxy.log"),
		MaxAge:       7,  // 日志保留7天
		RotationTime: 24, // 每24小时轮转一次
	}
	if err := logger.InitLogger(logConfig); err != nil {
		fmt.Printf("初始化日志系统失败: %v\n", err)
		os.Exit(1)
	}

	// 服务器命令
	serverCmd := flag.NewFlagSet("server", flag.ExitOnError)
	serverProxyPort := serverCmd.Int("p", 1080, "代理端口")
	serverTunnelPort := serverCmd.Int("u", 7000, "隧道端口")
	serverKey := serverCmd.String("k", "", "加密密钥")
	serverProtocol := serverCmd.String("t", "tcp", "传输协议 (tcp/kcp)")

	// 客户端命令
	clientCmd := flag.NewFlagSet("client", flag.ExitOnError)
	clientServer := clientCmd.String("s", "", "服务器地址")
	clientKey := clientCmd.String("k", "", "加密密钥")
	clientProtocol := clientCmd.String("t", "tcp", "传输协议 (tcp/kcp)")

	// 同时启动服务器和客户端的命令
	bothCmd := flag.NewFlagSet("both", flag.ExitOnError)
	bothProxyPort := bothCmd.Int("p", 1080, "代理端口")
	bothTunnelPort := bothCmd.Int("u", 7000, "隧道端口")
	bothKey := bothCmd.String("k", "", "加密密钥")
	bothProtocol := bothCmd.String("t", "tcp", "传输协议 (tcp/kcp)")

	// 解析命令
	if len(os.Args) < 2 {
		logger.Error("请指定命令: server/client/both")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "server":
		serverCmd.Parse(os.Args[2:])
		if *serverKey == "" {
			logger.Error("请指定加密密钥")
			os.Exit(1)
		}

		// 创建服务器
		s, err := server.NewServer(
			fmt.Sprintf(":%d", *serverProxyPort),
			fmt.Sprintf(":%d", *serverTunnelPort),
			[]byte(*serverKey),
			*serverProtocol,
		)
		if err != nil {
			logger.Error("创建服务器失败: %v", err)
			os.Exit(1)
		}

		// 监听退出信号
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

		// 启动服务器
		errChan := make(chan error, 1)
		go func() {
			errChan <- s.Start()
		}()

		// 等待退出信号或错误
		select {
		case <-sigChan:
			logger.Info("收到退出信号，正在关闭服务器...")
			s.Close()
		case err := <-errChan:
			if err != nil {
				logger.Error("服务器错误: %v", err)
			}
		}

	case "client":
		clientCmd.Parse(os.Args[2:])
		if *clientServer == "" {
			logger.Error("请指定服务器地址")
			os.Exit(1)
		}
		if *clientKey == "" {
			logger.Error("请指定加密密钥")
			os.Exit(1)
		}

		// 创建客户端
		c, err := client.NewClient(
			*clientServer,
			[]byte(*clientKey),
			*clientProtocol,
		)
		if err != nil {
			logger.Error("创建客户端失败: %v", err)
			os.Exit(1)
		}

		// 监听退出信号
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

		// 启动客户端
		errChan := make(chan error, 1)
		go func() {
			errChan <- c.Start()
		}()

		// 等待退出信号或错误
		select {
		case <-sigChan:
			logger.Info("收到退出信号，正在关闭客户端...")
			c.Close()
		case err := <-errChan:
			if err != nil {
				logger.Error("客户端错误: %v", err)
			}
		}

	case "both":
		bothCmd.Parse(os.Args[2:])
		if *bothKey == "" {
			logger.Error("请指定加密密钥")
			os.Exit(1)
		}

		// 创建服务器
		s, err := server.NewServer(
			fmt.Sprintf(":%d", *bothProxyPort),
			fmt.Sprintf(":%d", *bothTunnelPort),
			[]byte(*bothKey),
			*bothProtocol,
		)
		if err != nil {
			logger.Error("创建服务器失败: %v", err)
			os.Exit(1)
		}

		// 创建客户端
		c, err := client.NewClient(
			fmt.Sprintf("localhost:%d", *bothTunnelPort),
			[]byte(*bothKey),
			*bothProtocol,
		)
		if err != nil {
			logger.Error("创建客户端失败: %v", err)
			os.Exit(1)
		}

		// 监听退出信号
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

		// 启动服务器和客户端
		serverErrChan := make(chan error, 1)
		clientErrChan := make(chan error, 1)

		// 先启动服务器
		go func() {
			serverErrChan <- s.Start()
		}()

		// 等待服务器启动
		time.Sleep(time.Second) // 给服务器足够的启动时间

		// 启动客户端

		go func() {
			clientErrChan <- c.Start()
		}()

		// 等待退出信号或错误
		select {
		case <-sigChan:
			logger.Info("收到退出信号，正在关闭服务器和客户端...")
			s.Close()
			c.Close()
		case err := <-serverErrChan:
			if err != nil {
				logger.Error("服务器错误: %v", err)
			}
			c.Close()
		case err := <-clientErrChan:
			if err != nil {
				logger.Error("客户端错误: %v", err)
			}
			s.Close()
		}

	default:
		logger.Error("未知命令: %s", os.Args[1])
		os.Exit(1)
	}
}
