package main

// doh.go —— DoH 客户端：一是复用 HTTP/2 连接的代理 DNS 转发（queryDoHForProxy），
// 二是用于获取 ECH 配置的一次性 DoH 查询（queryDoH）及其 DNS 报文编解码工具。

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// queryDoHForProxy 通过 ECH 转发 DNS 查询到 Cloudflare DoH。
// 客户端按需创建并复用（HTTP/2 多路复用）；Stop 与 ECH 刷新时会失效重建。
func (r *proxyRuntime) queryDoHForProxy(dnsQuery []byte) ([]byte, error) {
	_, port, _, err := parseServerAddr(r.cfg.ServerAddr)
	if err != nil {
		return nil, err
	}

	dohURL := fmt.Sprintf("https://cloudflare-dns.com:%s/dns-query", port)

	// 复用 http.Client，利用 HTTP/2 多路复用，提升解析速度并防封锁
	r.dohMu.Lock()
	if r.dohClient == nil {
		echBytes, err := r.getECHList()
		if err != nil {
			r.dohMu.Unlock()
			return nil, fmt.Errorf("获取 ECH 配置失败: %w", err)
		}

		tlsCfg, err := buildTLSConfigWithECH("cloudflare-dns.com", echBytes)
		if err != nil {
			r.dohMu.Unlock()
			return nil, fmt.Errorf("构建 TLS 配置失败: %w", err)
		}

		transport := &http.Transport{
			TLSClientConfig:   tlsCfg,
			ForceAttemptHTTP2: true, // 强制开启 HTTP/2 多路复用
		}

		// 绑定物理网卡 IP（如果上一轮已定义）
		if r.cfg.ServerIP != "" {
			transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				_, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				dialer := &net.Dialer{
					Timeout: 10 * time.Second,
				}
				if r.localIP != nil {
					dialer.LocalAddr = &net.TCPAddr{IP: r.localIP, Port: 0}
				}
				return dialer.DialContext(ctx, network, net.JoinHostPort(r.cfg.ServerIP, port))
			}
		}

		r.dohClient = &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		}
	}
	client := r.dohClient
	r.dohMu.Unlock()

	// 发送 DoH 请求
	req, err := http.NewRequest("POST", dohURL, bytes.NewReader(dnsQuery))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := client.Do(req)
	if err != nil {
		// 如果网络断开或连接已死，清空复用池，以便下次重新建立
		r.invalidateDoHClient()
		return nil, fmt.Errorf("DoH 请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH 响应错误: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// queryDoH 执行 DoH 查询（用于获取 ECH 配置）
func queryDoH(domain, dohURL string) (string, error) {
	u, err := url.Parse(dohURL)
	if err != nil {
		return "", fmt.Errorf("无效的 DoH URL: %v", err)
	}

	dnsQuery := buildDNSQuery(domain, typeHTTPS)
	dnsBase64 := base64.RawURLEncoding.EncodeToString(dnsQuery)

	q := u.Query()
	q.Set("dns", dnsBase64)
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("创建请求失败: %v", err)
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("DoH 请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("DoH 服务器返回错误: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取 DoH 响应失败: %v", err)
	}

	return parseDNSResponse(body)
}

// buildDNSQuery 构建标准的 DNS 查询报文。
func buildDNSQuery(domain string, qtype uint16) []byte {
	query := make([]byte, 0, 512)
	query = append(query, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	for label := range strings.SplitSeq(domain, ".") {
		query = append(query, byte(len(label)))
		query = append(query, []byte(label)...)
	}
	query = append(query, 0x00, byte(qtype>>8), byte(qtype), 0x00, 0x01)
	return query
}

// parseDNSResponse 解析 DNS 响应报文，提取 HTTPS 记录中的 ECH 参数。
func parseDNSResponse(response []byte) (string, error) {
	if len(response) < 12 {
		return "", errors.New("响应过短")
	}
	ancount := binary.BigEndian.Uint16(response[6:8])
	if ancount == 0 {
		return "", errors.New("无应答记录")
	}

	offset := 12
	for offset < len(response) && response[offset] != 0 {
		offset += int(response[offset]) + 1
	}
	offset += 5

	for i := 0; i < int(ancount); i++ {
		if offset >= len(response) {
			break
		}
		if response[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			for offset < len(response) && response[offset] != 0 {
				offset += int(response[offset]) + 1
			}
			offset++
		}
		if offset+10 > len(response) {
			break
		}
		rrType := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 8
		dataLen := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 2
		if offset+int(dataLen) > len(response) {
			break
		}
		data := response[offset : offset+int(dataLen)]
		offset += int(dataLen)

		if rrType == typeHTTPS {
			if ech := parseHTTPSRecord(data); ech != "" {
				return ech, nil
			}
		}
	}
	return "", nil
}

// parseHTTPSRecord 从 HTTPS 记录中解析 ECH 配置（Base64 编码）。
func parseHTTPSRecord(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	offset := 2
	if offset < len(data) && data[offset] == 0 {
		offset++
	} else {
		for offset < len(data) && data[offset] != 0 {
			offset += int(data[offset]) + 1
		}
		offset++
	}
	for offset+4 <= len(data) {
		key := binary.BigEndian.Uint16(data[offset : offset+2])
		length := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4
		if offset+int(length) > len(data) {
			break
		}
		value := data[offset : offset+int(length)]
		offset += int(length)
		if key == 5 {
			return base64.StdEncoding.EncodeToString(value)
		}
	}
	return ""
}
