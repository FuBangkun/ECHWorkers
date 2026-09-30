package main

// DNS 缓存：UDP:53 劫持路径（见 tun.go handleDNSViaDoH）的查询级缓存。
// key 为 question 段（name+type+class），命中时重写响应报文的 ID 后直接回包，
// 免去一次 DoH 往返。TTL 取应答记录的最小值并钳制到 [30s, 600s]；
// NXDOMAIN/NODATA 按 60s 做负缓存。

import (
	"encoding/binary"
	"strings"
	"sync"
	"time"
)

const (
	dnsCacheMaxEntries = 1024
	dnsCacheMinTTL     = 30
	dnsCacheMaxTTL     = 600
	dnsCacheNegTTL     = 60 // NXDOMAIN / NODATA 负缓存
)

type dnsCacheEntry struct {
	resp   []byte
	expire time.Time
}

var (
	dnsCacheMu sync.Mutex
	dnsCache   = make(map[string]dnsCacheEntry)
)

// parseDNSQuestion 提取标准查询（opcode=0）的 question 段，
// 返回缓存 key 与 query ID。解析失败 ok=false（调用方直接走 DoH，不走缓存）。
func parseDNSQuestion(dnsQuery []byte) (key string, qid uint16, ok bool) {
	if len(dnsQuery) < 12+5 { // 头部 12 + 最短 question（根 + type + class = 5）
		return "", 0, false
	}
	flags := binary.BigEndian.Uint16(dnsQuery[2:4])
	if flags&0x8000 != 0 { // QR=1 是响应不是查询
		return "", 0, false
	}
	if (flags>>11)&0x0F != 0 { // 仅缓存标准查询（opcode=0）
		return "", 0, false
	}
	qdcount := binary.BigEndian.Uint16(dnsQuery[4:6])
	if qdcount < 1 {
		return "", 0, false
	}

	qid = binary.BigEndian.Uint16(dnsQuery[0:2])
	pos := 12
	var name strings.Builder
	for {
		if pos >= len(dnsQuery) {
			return "", 0, false
		}
		l := int(dnsQuery[pos])
		pos++
		if l == 0 {
			break
		}
		if l > 63 || pos+l > len(dnsQuery) {
			return "", 0, false
		}
		name.Write(dnsQuery[pos : pos+l])
		name.WriteByte('.')
		pos += l
	}
	if pos+4 > len(dnsQuery) {
		return "", 0, false
	}
	qtype := binary.BigEndian.Uint16(dnsQuery[pos : pos+2])
	qclass := binary.BigEndian.Uint16(dnsQuery[pos+2 : pos+4])

	return strings.ToLower(name.String()) + "|" +
		itoa(int(qtype)) + "|" + itoa(int(qclass)), qid, true
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var b [5]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

// parseRespMeta 解析 DoH 应答：返回 rcode、答案记录数与最小 TTL（秒）。
// 支持 NAME 压缩指针（0xC0 前缀）。解析失败 ok=false。
func parseRespMeta(resp []byte) (rcode int, ancount int, minTTL uint32, ok bool) {
	if len(resp) < 12 {
		return 0, 0, 0, false
	}
	ancount = int(binary.BigEndian.Uint16(resp[6:8]))
	rcode = int(resp[3] & 0x0F)

	// 跳过 question 段（取第一个）
	qdcount := int(binary.BigEndian.Uint16(resp[4:6]))
	pos := 12
	for range qdcount {
		for {
			if pos >= len(resp) {
				return 0, 0, 0, false
			}
			l := int(resp[pos])
			pos++
			if l == 0 {
				break
			}
			if l > 63 {
				return 0, 0, 0, false
			}
			pos += l
		}
		pos += 4 // QTYPE + QCLASS
	}

	minTTL = ^uint32(0)
	for i := 0; i < ancount; i++ {
		// NAME：压缩指针 2 字节，或标签序列至 0
		if pos >= len(resp) {
			return 0, 0, 0, false
		}
		if resp[pos]&0xC0 == 0xC0 {
			pos += 2
		} else {
			for {
				if pos >= len(resp) {
					return 0, 0, 0, false
				}
				l := int(resp[pos])
				pos++
				if l == 0 {
					break
				}
				if l > 63 {
					return 0, 0, 0, false
				}
				pos += l
			}
		}
		if pos+10 > len(resp) {
			return 0, 0, 0, false
		}
		ttl := binary.BigEndian.Uint32(resp[pos+4 : pos+8])
		rdlen := int(binary.BigEndian.Uint16(resp[pos+8 : pos+10]))
		pos += 10 + rdlen
		if ttl < minTTL {
			minTTL = ttl
		}
	}
	if ancount == 0 {
		minTTL = 0
	}
	return rcode, ancount, minTTL, true
}

// dnsCacheLookup 查缓存；命中返回重写了本次查询 ID 的响应副本。
func dnsCacheLookup(dnsQuery []byte) ([]byte, bool) {
	key, qid, ok := parseDNSQuestion(dnsQuery)
	if !ok {
		return nil, false
	}
	dnsCacheMu.Lock()
	defer dnsCacheMu.Unlock()
	e, hit := dnsCache[key]
	if !hit {
		return nil, false
	}
	if time.Now().After(e.expire) {
		delete(dnsCache, key)
		return nil, false
	}
	out := make([]byte, len(e.resp))
	copy(out, e.resp)
	binary.BigEndian.PutUint16(out[0:2], qid) // 响应 ID 改写为本次查询的 ID
	return out, true
}

// dnsCacheStore 存入 DoH 响应（按应答内容决定 TTL）。
func dnsCacheStore(dnsQuery, resp []byte) {
	key, _, ok := parseDNSQuestion(dnsQuery)
	if !ok {
		return
	}
	ttl := dnsCacheNegTTL
	if rcode, ancount, minTTL, pok := parseRespMeta(resp); pok {
		switch {
		case rcode != 0 || ancount == 0:
			ttl = dnsCacheNegTTL
		default:
			ttl = min(max(int(minTTL), dnsCacheMinTTL), dnsCacheMaxTTL)
		}
	} else {
		return // 报文异常不入缓存
	}

	dnsCacheMu.Lock()
	defer dnsCacheMu.Unlock()
	if len(dnsCache) >= dnsCacheMaxEntries {
		now := time.Now()
		for k, e := range dnsCache {
			if now.After(e.expire) {
				delete(dnsCache, k)
			}
		}
		if len(dnsCache) >= dnsCacheMaxEntries {
			dnsCache = make(map[string]dnsCacheEntry) // 兜底：直接清空重建
		}
	}
	cp := make([]byte, len(resp))
	copy(cp, resp)
	dnsCache[key] = dnsCacheEntry{resp: cp, expire: time.Now().Add(time.Duration(ttl) * time.Second)}
}
