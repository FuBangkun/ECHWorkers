package main

// ech.go —— ECH 配置管理：通过 DoH 查询 HTTPS(type=65) 记录，
// 提取并缓存 ECH 配置，供拨号层（dial.go）构建 TLS 配置使用。

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"strings"
)

const typeHTTPS = 65

func (r *proxyRuntime) prepareECH() error {
	echBase64, err := queryHTTPSRecord(r.cfg.ECHDomain, r.cfg.DNSServer)
	if err != nil {
		return fmt.Errorf("DNS 查询失败: %w", err)
	}
	if echBase64 == "" {
		return errors.New("未找到 ECH 参数")
	}
	raw, err := base64.StdEncoding.DecodeString(echBase64)
	if err != nil {
		return fmt.Errorf("ECH 解码失败: %w", err)
	}
	r.echMu.Lock()
	r.echList = raw
	r.echMu.Unlock()
	log.Printf("[ECH] 配置已加载，长度: %d 字节", len(raw))
	return nil
}

// refreshECH 刷新 ECH 配置（通常在连接失败时调用）。
// ECH 配置变化会使 DoH 客户端内嵌的旧 TLS 配置失效，一并重建。
func (r *proxyRuntime) refreshECH() error {
	log.Printf("[ECH] 刷新配置...")
	if err := r.prepareECH(); err != nil {
		return err
	}
	r.invalidateDoHClient()
	return nil
}

// getECHList 返回当前缓存的 ECH 配置（线程安全）。
func (r *proxyRuntime) getECHList() ([]byte, error) {
	r.echMu.RLock()
	defer r.echMu.RUnlock()
	if len(r.echList) == 0 {
		return nil, errors.New("ECH 配置未加载")
	}
	return r.echList, nil
}

// queryHTTPSRecord 通过 DoH 查询域名的 HTTPS 记录，用于获取 ECH 配置。
func queryHTTPSRecord(domain, dnsServer string) (string, error) {
	dohURL := dnsServer
	if !strings.HasPrefix(dohURL, "https://") && !strings.HasPrefix(dohURL, "http://") {
		dohURL = "https://" + dohURL
	}
	return queryDoH(domain, dohURL)
}
