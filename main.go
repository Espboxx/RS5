package main

import (
	"log"

	"reverseproxy/client"
	"reverseproxy/server"

	"github.com/spf13/cobra"
)

// 服务端参数
var (
	serverSocksPort  int
	serverTunnelPort int
	serverKey        string
	serverUsername   string
	serverPassword   string
)

// 客户端参数
var (
	clientServerHost string
	clientTunnelPort int
	clientKey        string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "reverseproxy",
		Short: "SOCKS5反向代理工具",
	}

	serverCmd := &cobra.Command{
		Use:   "server",
		Short: "启动代理服务端",
		Run:   server.RunServer,
	}

	clientCmd := &cobra.Command{
		Use:   "client",
		Short: "启动代理客户端",
		Run: func(cmd *cobra.Command, args []string) {
			client.RunClient(cmd, args)
		},
	}

	// 服务端参数
	serverCmd.Flags().IntVarP(&serverSocksPort, "socks", "p", 1080, "SOCKS5代理端口")
	serverCmd.Flags().IntVarP(&serverTunnelPort, "tunnel", "u", 7000, "隧道端口")
	serverCmd.Flags().StringVarP(&serverKey, "key", "k", "default-key", "加密密钥")
	serverCmd.Flags().StringVarP(&serverUsername, "username", "U", "user1", "SOCKS5认证用户名")
	serverCmd.Flags().StringVarP(&serverPassword, "password", "P", "pass1", "SOCKS5认证密码")

	// 客户端参数
	clientCmd.Flags().StringVarP(&clientServerHost, "server", "c", "localhost", "服务器地址")
	clientCmd.Flags().IntVarP(&clientTunnelPort, "tunnel", "n", 7000, "隧道端口")
	clientCmd.Flags().StringVarP(&clientKey, "key", "e", "default-key", "加密密钥")

	rootCmd.AddCommand(serverCmd, clientCmd)

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
