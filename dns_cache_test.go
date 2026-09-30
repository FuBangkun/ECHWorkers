package main

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

// buildTestQuery 构造一个标准 A 查询：www.example.com A IN，ID=0x1234
func buildTestQuery(t *testing.T, qid uint16) []byte {
	t.Helper()
	q := []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // flags: RD=1, opcode=0, QR=0
		0x00, 0x01, // QDCOUNT
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		0, 1, // QTYPE=A
		0, 1, // QCLASS=IN
	}
	binary.BigEndian.PutUint16(q[0:2], qid)
	return q
}

// buildTestResponse 构造带 2 条 A 记录的应答（TTL 分别为 120 / 300），ID=0xFFFF
func buildTestResponse(t *testing.T) []byte {
	t.Helper()
	qname := []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	r := []byte{
		0xFF, 0xFF, // ID
		0x81, 0x80, // QR=1, RD=1, RA=1
		0x00, 0x01, // QDCOUNT
		0x00, 0x02, // ANCOUNT
		0x00, 0x00, 0x00, 0x00,
	}
	r = append(r, qname...)
	r = append(r, 0, 1, 0, 1) // question: A IN

	// 答案 1：NAME 压缩指针指向 question（0xC00C），TTL=120
	ans := append([]byte{0xC0, 0x0C}, 0, 1, 0, 1)
	ans = append(ans, 0, 0, 0, 120) // TTL
	ans = append(ans, 0, 4)         // RDLENGTH
	ans = append(ans, 93, 184, 216, 34)
	r = append(r, ans...)

	// 答案 2：NAME 完整写出，TTL=300
	ans2 := append([]byte{}, qname...)
	ans2 = append(ans2, 0, 1, 0, 1)
	ans2 = append(ans2, 0, 0, 1, 44) // TTL=300
	ans2 = append(ans2, 0, 4)
	ans2 = append(ans2, 1, 2, 3, 4)
	r = append(r, ans2...)

	return r
}

func TestDNSCacheHitRewritesID(t *testing.T) {
	query := buildTestQuery(t, 0x1234)
	resp := buildTestResponse(t) // ID=0xFFFF

	if _, hit := dnsCacheLookup(query); hit {
		t.Fatal("存入前不应命中")
	}
	dnsCacheStore(query, resp)

	cached, hit := dnsCacheLookup(query)
	if !hit {
		t.Fatal("存入后应命中")
	}
	if got := binary.BigEndian.Uint16(cached[0:2]); got != 0x1234 {
		t.Fatalf("命中报文 ID 应重写为 0x1234，实际 %x", got)
	}
	if !bytes.Equal(cached[2:], resp[2:]) {
		t.Fatal("命中报文除 ID 外内容应与原响应一致")
	}
	// 另一个 ID 的同内容查询也应命中（ID 不参与 key）
	if _, hit := dnsCacheLookup(buildTestQuery(t, 0xABCD)); !hit {
		t.Fatal("不同 ID 的同内容查询应命中")
	}
}

func TestDNSCacheTTLClamp(t *testing.T) {
	query := buildTestQuery(t, 0x0001)
	resp := buildTestResponse(t) // minTTL=120，应原样保留
	dnsCacheStore(query, resp)

	dnsCacheMu.Lock()
	e := dnsCache["www.example.com.|1|1"]
	dnsCacheMu.Unlock()
	remaining := time.Until(e.expire)
	if remaining < 100*time.Second || remaining > 125*time.Second {
		t.Fatalf("TTL 应取应答最小值 120s，实际剩余 %v", remaining)
	}
}

func TestDNSCacheMissOnCaseDifference(t *testing.T) {
	query := buildTestQuery(t, 0x0002)
	// 大小写不同的域名（WwW.Example.COM）应命中同一 key（DNS 大小写不敏感）
	dnsCacheStore(query, buildTestResponse(t))
	upper := []byte{
		0x00, 0x02, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0,
		3, 'W', 'W', 'W', 7, 'E', 'X', 'A', 'M', 'P', 'L', 'E', 3, 'C', 'O', 'M', 0,
		0, 1, 0, 1,
	}
	if _, hit := dnsCacheLookup(upper); !hit {
		t.Fatal("大小写不同的同域名应命中")
	}
}

func TestDNSCacheNonStandardQueryBypassed(t *testing.T) {
	resp := buildTestResponse(t)
	// QR=1（响应报文）不应入缓存
	bad := buildTestQuery(t, 0x0003)
	bad[2] = 0x81 // QR=1
	dnsCacheStore(bad, resp)
	if _, hit := dnsCacheLookup(bad); hit {
		t.Fatal("QR=1 的报文不应入缓存")
	}
}

func TestDNSCacheExpiry(t *testing.T) {
	query := buildTestQuery(t, 0x0004)
	dnsCacheStore(query, buildTestResponse(t))
	key := "www.example.com.|1|1"

	dnsCacheMu.Lock()
	e := dnsCache[key]
	e.expire = time.Now().Add(-time.Second) // 手动过期
	dnsCache[key] = e
	dnsCacheMu.Unlock()

	if _, hit := dnsCacheLookup(query); hit {
		t.Fatal("过期条目不应命中")
	}
	dnsCacheMu.Lock()
	_, exists := dnsCache[key]
	dnsCacheMu.Unlock()
	if exists {
		t.Fatal("过期条目应被删除")
	}
}
