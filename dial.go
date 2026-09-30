package main

// dial.go —— 出站连接拨号层：构建带 ECH 的 TLS 配置，
// 并在此基础上建立到 Worker 的 WebSocket 连接（含 ECH 失败自动刷新重试）。

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// tlsSessionCache 包级共享的 TLS 会话缓存：config 每次拨号重建（ECH 配置可刷新），
// 但缓存对象保持复用，使 mux 会话与 DoH 连接能复用 TLS 会话（PSK），省去证书链
// 解析与签名验证开销。注意：Go 的 TLS 1.3 PSK 恢复不省 RTT（无 0-RTT），收益在 CPU。
var tlsSessionCache = tls.NewLRUClientSessionCache(64)

func buildTLSConfigWithECH(serverName string, echList []byte) (*tls.Config, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("加载系统根证书失败: %w", err)
	}

	if len(echList) == 0 {
		return nil, errors.New("ECH 配置为空，这是必需功能")
	}

	config := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         serverName,
		RootCAs:            roots,
		ClientSessionCache: tlsSessionCache,
	}

	// 使用反射设置 ECH 字段（ECH 是核心功能，必须设置成功）
	if err := setECHConfig(config, echList); err != nil {
		return nil, fmt.Errorf("设置 ECH 配置失败（需要 Go 1.23+ 或支持 ECH 的版本）: %w", err)
	}

	return config, nil
}

// setECHConfig 使用反射设置 ECH 配置（ECH 是核心功能，必须成功）
func setECHConfig(config *tls.Config, echList []byte) error {
	configValue := reflect.ValueOf(config).Elem()

	// 设置 EncryptedClientHelloConfigList（必需）
	field1 := configValue.FieldByName("EncryptedClientHelloConfigList")
	if !field1.IsValid() || !field1.CanSet() {
		return fmt.Errorf("EncryptedClientHelloConfigList 字段不可用，需要 Go 1.23+ 版本")
	}
	field1.Set(reflect.ValueOf(echList))

	// 设置 EncryptedClientHelloRejectionVerify（必需）
	field2 := configValue.FieldByName("EncryptedClientHelloRejectionVerify")
	if !field2.IsValid() || !field2.CanSet() {
		return fmt.Errorf("EncryptedClientHelloRejectionVerify 字段不可用，需要 Go 1.23+ 版本")
	}
	rejectionFunc := func(cs tls.ConnectionState) error {
		return errors.New("服务器拒绝 ECH")
	}
	field2.Set(reflect.ValueOf(rejectionFunc))

	return nil
}

// parseServerAddr 解析服务器地址，返回 host、port、path 和错误信息。
func parseServerAddr(addr string) (host, port, path string, err error) {
	path = "/"
	slashIdx := strings.Index(addr, "/")
	if slashIdx != -1 {
		path = addr[slashIdx:]
		addr = addr[:slashIdx]
	}

	host, port, err = net.SplitHostPort(addr)
	if err != nil {
		return "", "", "", fmt.Errorf("无效的服务器地址格式: %v", err)
	}

	return host, port, path, nil
}

// dialWebSocketWithECH 使用 ECH 配置建立到 Worker 的 WebSocket 连接，支持自动重试。
func (r *proxyRuntime) dialWebSocketWithECH(maxRetries int) (*websocket.Conn, error) {
	host, port, path, err := parseServerAddr(r.cfg.ServerAddr)
	if err != nil {
		return nil, err
	}

	wsURL := fmt.Sprintf("wss://%s:%s%s", host, port, path)

	for attempt := 1; attempt <= maxRetries; attempt++ {
		echBytes, echErr := r.getECHList()
		if echErr != nil {
			if attempt < maxRetries {
				r.refreshECH()
				continue
			}
			return nil, echErr
		}

		tlsCfg, tlsErr := buildTLSConfigWithECH(host, echBytes)
		if tlsErr != nil {
			return nil, tlsErr
		}

		dialer := websocket.Dialer{
			TLSClientConfig: tlsCfg,
			Subprotocols: func() []string {
				if r.cfg.Token == "" {
					return nil
				}
				return []string{r.cfg.Token}
			}(),
			HandshakeTimeout: 10 * time.Second,
		}

		if r.cfg.ServerIP != "" {
			dialer.NetDial = func(network, address string) (net.Conn, error) {
				_, port, err := net.SplitHostPort(address)
				if err != nil {
					return nil, err
				}
				d := &net.Dialer{
					Timeout: 10 * time.Second,
				}
				// 绑定物理网卡 IP，防止出站流量再次进入 TUN（防死循环）
				if r.localIP != nil {
					d.LocalAddr = &net.TCPAddr{IP: r.localIP, Port: 0}
				}
				return d.Dial(network, net.JoinHostPort(r.cfg.ServerIP, port))
			}
		}

		wsConn, resp, dialErr := dialer.Dial(wsURL, nil)
		if dialErr != nil {
			// gorilla 在握手失败时返回服务端的 HTTP 响应，把状态码打出来便于定位
			// （401=token 不匹配 / 426=非 WS 请求 / 404 5xx=worker 未部署或异常）
			if resp != nil {
				log.Printf("[WS] 握手被服务端拒绝: HTTP %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
			}
			if strings.Contains(dialErr.Error(), "ECH") && attempt < maxRetries {
				log.Printf("[ECH] 连接失败，尝试刷新配置 (%d/%d)", attempt, maxRetries)
				r.refreshECH()
				time.Sleep(time.Second)
				continue
			}
			return nil, dialErr
		}

		return wsConn, nil
	}

	return nil, errors.New("连接失败，已达最大重试次数")
}
