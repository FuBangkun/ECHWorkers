package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// muxServeSession 用 Go 复刻 _worker.js 的服务端逻辑，用于本地回环测试。
func muxServeSession(ws *websocket.Conn) {
	streams := make(map[uint32]net.Conn)
	var mu sync.Mutex
	var sendMu sync.Mutex // gorilla 不允许并发写，JS 端无此问题（单线程 send 同步入队）
	defer func() {
		mu.Lock()
		for _, c := range streams {
			c.Close()
		}
		mu.Unlock()
		ws.Close()
	}()

	send := func(ftype byte, sid uint32, payload []byte) {
		sendMu.Lock()
		defer sendMu.Unlock()
		_ = ws.WriteMessage(websocket.BinaryMessage, muxEncodeFrame(ftype, sid, payload))
	}

	for {
		mt, data, err := ws.ReadMessage()
		if err != nil {
			return
		}
		if mt != websocket.BinaryMessage || len(data) < muxHeaderLen {
			continue
		}
		ftype := data[0]
		sid := binary.BigEndian.Uint32(data[1:5])
		plen := int(binary.BigEndian.Uint16(data[5:7]))
		if muxHeaderLen+plen > len(data) {
			continue
		}
		payload := data[muxHeaderLen:]

		switch ftype {
		case muxFrameSYN:
			mu.Lock()
			_, exists := streams[sid]
			mu.Unlock()
			if exists {
				continue
			}
			c, dialErr := net.DialTimeout("tcp", string(payload), 2*time.Second)
			if dialErr != nil {
				send(muxFrameOPENED, sid, []byte("ERR:"+dialErr.Error()))
				continue
			}
			mu.Lock()
			streams[sid] = c
			mu.Unlock()
			send(muxFrameOPENED, sid, nil)
			go func() {
				buf := make([]byte, muxMaxPayload)
				for {
					n, readErr := c.Read(buf)
					if n > 0 {
						send(muxFrameDATA, sid, buf[:n])
					}
					if readErr != nil {
						send(muxFrameFIN, sid, nil)
						mu.Lock()
						delete(streams, sid)
						mu.Unlock()
						c.Close()
						return
					}
				}
			}()
		case muxFrameDATA:
			mu.Lock()
			c := streams[sid]
			mu.Unlock()
			if c != nil {
				_, _ = c.Write(payload)
			}
		case muxFrameFIN, muxFrameRST:
			mu.Lock()
			c := streams[sid]
			delete(streams, sid)
			mu.Unlock()
			if c != nil {
				c.Close()
			}
		}
	}
}

func startEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				io.Copy(c, c)
				c.Close()
			}(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

func newTestSession(t *testing.T) *muxSession {
	t.Helper()
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		muxServeSession(ws)
	}))
	t.Cleanup(srv.Close)

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ws.Close() })
	return newMuxSession(ws, newMuxSessionPool())
}

func readWithTimeout(t *testing.T, s *muxStream, buf []byte) (int, error) {
	t.Helper()
	type result struct {
		n   int
		err error
	}
	ch := make(chan result, 1)
	go func() {
		n, err := s.Read(buf)
		ch <- result{n, err}
	}()
	select {
	case r := <-ch:
		return r.n, r.err
	case <-time.After(3 * time.Second):
		t.Fatal("读取超时")
		return 0, nil
	}
}

func TestMuxStreamEcho(t *testing.T) {
	echoAddr := startEchoServer(t)
	sess := newTestSession(t)

	stream, err := sess.openStream(echoAddr)
	if err != nil {
		t.Fatalf("openStream: %v", err)
	}
	defer stream.Close()

	msg := []byte("hello mux")
	if _, err := stream.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	n, err := readWithTimeout(t, stream, buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(buf[:n], msg) {
		t.Fatalf("回显不匹配: got %q want %q", buf[:n], msg)
	}
}

func TestMuxConcurrentStreams(t *testing.T) {
	echoAddr := startEchoServer(t)
	sess := newTestSession(t)

	var wg sync.WaitGroup
	for i := range muxStreamsPerSession {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s, err := sess.openStream(echoAddr)
			if err != nil {
				t.Errorf("open %d: %v", i, err)
				return
			}
			defer s.Close()

			payload := bytes.Repeat([]byte{byte('A' + i)}, 4096)
			if _, err := s.Write(payload); err != nil {
				t.Errorf("write %d: %v", i, err)
				return
			}
			buf := make([]byte, len(payload))
			got := 0
			for got < len(payload) {
				n, err := s.Read(buf[got:])
				if err != nil {
					t.Errorf("read %d: %v", i, err)
					return
				}
				got += n
			}
			if !bytes.Equal(buf, payload) {
				t.Errorf("流 %d 数据不匹配", i)
			}
		}(i)
	}
	wg.Wait()
}

func TestMuxStreamEOFOnServerClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close() // 立即关闭 → 服务端发 FIN → 客户端应读到 EOF
		}
	}()

	sess := newTestSession(t)
	stream, err := sess.openStream(ln.Addr().String())
	if err != nil {
		t.Fatalf("openStream: %v", err)
	}
	defer stream.Close()

	buf := make([]byte, 16)
	_, err = readWithTimeout(t, stream, buf)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("期望 EOF，得到 %v", err)
	}
}

func TestMuxStreamRefused(t *testing.T) {
	sess := newTestSession(t)
	_, err := sess.openStream("127.0.0.1:1") // 端口 1 必然拒绝
	if !errors.Is(err, errMuxRefused) {
		t.Fatalf("期望拒绝错误，得到 %v", err)
	}
}
