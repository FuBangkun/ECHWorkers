package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// mux 帧协议：1 条 WS 二进制消息 = 1 帧（利用 WS 消息原子性，无粘包问题）
//
//	+--------+------------+--------+------------------+
//	| type 1B| streamID 4B| len 2B | payload (≤32KB)  |
//	+--------+------------+--------+------------------+
//
// 服务端对应实现在 _worker.js。客户端与服务端必须同时升级，互不兼容旧协议。
const (
	muxFrameSYN    = 0x01 // C→W 开流，payload = "host:port"
	muxFrameOPENED = 0x02 // W→C 流已建立（payload 以 "ERR:" 开头表示失败）
	muxFrameDATA   = 0x03 // 双向流数据
	muxFrameFIN    = 0x04 // W→C 远端写完（EOF）
	muxFrameRST    = 0x05 // 双向异常中止流

	muxHeaderLen  = 7
	muxMaxPayload = 32 * 1024

	muxStreamsPerSession = 5  // CF Workers 每次调用并发出站 socket 上限 6，留 1 余量
	muxMaxSessions       = 16 // 会话池上限（16 × 5 = 80 并发流）
	muxReadQSize         = 64 // 每流读队列帧数（背压）

	muxPingEvery   = 10 * time.Second // 会话保活间隔（WS 协议层 ping/pong）
	muxOpenTimeout = 10 * time.Second // 开流超时
	muxWriteIdle   = 15 * time.Second // 单帧写超时
)

var (
	errSessionDead  = errors.New("mux: 会话已关闭")
	errSessionFull  = errors.New("mux: 会话流数已满")
	errMuxRefused   = errors.New("服务端拒绝连接")
	errMuxPoolEmpty = errors.New("mux: 会话池已满且无空闲容量")
)

// muxEncodeFrame 编码一帧。
func muxEncodeFrame(ftype byte, sid uint32, payload []byte) []byte {
	buf := make([]byte, muxHeaderLen+len(payload))
	buf[0] = ftype
	binary.BigEndian.PutUint32(buf[1:5], sid)
	binary.BigEndian.PutUint16(buf[5:7], uint16(len(payload)))
	copy(buf[muxHeaderLen:], payload)
	return buf
}

// ============================================================
// muxStream —— 实现 net.Conn，直接对接 gVisor 的 gonet 连接
// ============================================================

type muxStream struct {
	sid       uint32
	session   *muxSession
	readCh    chan []byte // DATA 帧队列（读泵填充）
	readBuf   []byte      // 当前帧未读完部分
	die       chan struct{}
	closeOnce sync.Once
	finOnce   sync.Once
	finRecv   bool  // 仅读泵 goroutine 访问：已收到 FIN，后续 DATA 帧丢弃
	rstErr    error // kill 时记录的终止原因
}

func (s *muxStream) readErr() error {
	if s.rstErr != nil {
		return s.rstErr
	}
	return net.ErrClosed
}

// kill 终止流：记录原因并唤醒所有阻塞的读写。只应通过 closeOnce 调用一次。
func (s *muxStream) kill(err error) {
	s.closeOnce.Do(func() {
		if err != nil && s.rstErr == nil {
			s.rstErr = err
		}
		close(s.die)
	})
}

func (s *muxStream) Read(p []byte) (int, error) {
	for {
		if len(s.readBuf) > 0 {
			n := copy(p, s.readBuf)
			s.readBuf = s.readBuf[n:]
			return n, nil
		}
		select {
		case <-s.die:
			return 0, s.readErr()
		case frame, ok := <-s.readCh:
			if !ok {
				return 0, io.EOF // 收到 FIN：远端写完
			}
			s.readBuf = frame
		}
	}
}

func (s *muxStream) Write(p []byte) (int, error) {
	sent := 0
	for sent < len(p) {
		end := min(sent+muxMaxPayload, len(p))
		frame := muxEncodeFrame(muxFrameDATA, s.sid, p[sent:end])
		select {
		case <-s.die:
			return sent, s.readErr()
		case s.session.writeCh <- frame:
			sent = end
		}
	}
	return sent, nil
}

// Close 关闭并中止流（全关闭语义：向对端发送 RST，同旧协议的 CLOSE 行为）。
func (s *muxStream) Close() error {
	s.kill(nil)
	sess := s.session
	sess.removeStream(s.sid)
	select {
	case sess.writeCh <- muxEncodeFrame(muxFrameRST, s.sid, nil):
	default: // 写队列满时丢弃 RST：对端会随会话/流状态自行清理
	}
	return nil
}

func (s *muxStream) LocalAddr() net.Addr                { return muxAddr{} }
func (s *muxStream) RemoteAddr() net.Addr               { return muxAddr{} }
func (s *muxStream) SetDeadline(t time.Time) error      { return nil }
func (s *muxStream) SetReadDeadline(t time.Time) error  { return nil }
func (s *muxStream) SetWriteDeadline(t time.Time) error { return nil }

type muxAddr struct{}

func (muxAddr) Network() string { return "mux" }
func (muxAddr) String() string  { return "mux" }

// ============================================================
// muxSession —— 一条 ECH+TLS+WS 长连接上的复用会话
// ============================================================

type muxSession struct {
	ws      *websocket.Conn
	pool    *muxSessionPool
	writeCh chan []byte // 写泵消费的帧队列

	mu          sync.Mutex
	streams     map[uint32]*muxStream
	nextID      uint32
	streamCount int

	die     chan struct{}
	dieOnce sync.Once
}

func newMuxSession(ws *websocket.Conn, pool *muxSessionPool) *muxSession {
	sess := &muxSession{
		ws:      ws,
		pool:    pool,
		writeCh: make(chan []byte, 128),
		streams: make(map[uint32]*muxStream),
		die:     make(chan struct{}),
	}
	go sess.readPump()
	go sess.writePump()
	go sess.pingLoop()
	return sess
}

func (sess *muxSession) count() int {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	return sess.streamCount
}

func (sess *muxSession) alive() bool {
	select {
	case <-sess.die:
		return false
	default:
		return true
	}
}

// shutdown 关闭会话并 RST 所有流（幂等）。
func (sess *muxSession) shutdown(err error) {
	sess.dieOnce.Do(func() {
		if err != nil && !errors.Is(err, io.EOF) &&
			!websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
			log.Printf("[MUX] 会话异常关闭: %v", err)
		}
		close(sess.die)
		sess.mu.Lock()
		streams := sess.streams
		sess.streams = make(map[uint32]*muxStream)
		sess.streamCount = 0
		sess.mu.Unlock()
		for _, s := range streams {
			s.kill(errSessionDead)
		}
		sess.ws.Close()
	})
	sess.pool.wake()
}

// openStream SYN → OPENED 握手。流必须先注册进会话（读泵按 sid 分发），
// 注册失败/超时路径统一走 cleanup 回收。
func (sess *muxSession) openStream(target string) (*muxStream, error) {
	sess.mu.Lock()
	if sess.streamCount >= muxStreamsPerSession {
		sess.mu.Unlock()
		return nil, errSessionFull
	}
	if !sess.alive() {
		sess.mu.Unlock()
		return nil, errSessionDead
	}
	sid := sess.nextID
	sess.nextID++
	s := &muxStream{
		sid:     sid,
		session: sess,
		readCh:  make(chan []byte, muxReadQSize),
		die:     make(chan struct{}),
	}
	sess.streams[sid] = s
	sess.streamCount++
	sess.mu.Unlock()

	cleanup := func() {
		sess.mu.Lock()
		if _, ok := sess.streams[sid]; ok {
			delete(sess.streams, sid)
			sess.streamCount--
		}
		sess.mu.Unlock()
		sess.pool.wake()
	}

	select {
	case sess.writeCh <- muxEncodeFrame(muxFrameSYN, sid, []byte(target)):
	case <-sess.die:
		cleanup()
		return nil, errSessionDead
	case <-time.After(muxOpenTimeout):
		cleanup()
		return nil, fmt.Errorf("mux: SYN 发送超时")
	}

	select {
	case <-sess.die:
		cleanup()
		return nil, errSessionDead
	case payload, ok := <-s.readCh:
		if !ok {
			cleanup()
			return nil, errors.New("mux: 流被对端关闭")
		}
		if len(payload) >= 4 && string(payload[:4]) == "ERR:" {
			s.kill(nil)
			cleanup()
			return nil, fmt.Errorf("%w: %s", errMuxRefused, string(payload[4:]))
		}
		return s, nil
	case <-time.After(muxOpenTimeout):
		cleanup()
		return nil, fmt.Errorf("mux: OPENED 超时")
	}
}

func (sess *muxSession) removeStream(sid uint32) {
	sess.mu.Lock()
	if _, ok := sess.streams[sid]; ok {
		delete(sess.streams, sid)
		sess.streamCount--
	}
	sess.mu.Unlock()
	sess.pool.wake()
}

// readPump 读泵：解析帧并按 streamID 分发。读失败即会话死亡。
func (sess *muxSession) readPump() {
	for {
		mt, data, err := sess.ws.ReadMessage()
		if err != nil {
			sess.shutdown(err)
			return
		}
		if mt != websocket.BinaryMessage || len(data) < muxHeaderLen {
			continue
		}
		ftype := data[0]
		sid := binary.BigEndian.Uint32(data[1:5])
		plen := int(binary.BigEndian.Uint16(data[5:7]))
		if muxHeaderLen+plen > len(data) {
			continue // 长度不符的帧直接丢弃
		}
		payload := data[muxHeaderLen:]

		sess.mu.Lock()
		s := sess.streams[sid]
		sess.mu.Unlock()
		if s == nil {
			continue
		}

		switch ftype {
		case muxFrameOPENED, muxFrameDATA:
			if s.finRecv {
				continue
			}
			select {
			case s.readCh <- payload:
			case <-s.die:
			}
		case muxFrameFIN:
			s.finRecv = true
			s.finOnce.Do(func() { close(s.readCh) })
		case muxFrameRST:
			s.kill(errors.New("mux: 对端重置流"))
		}
	}
}

// writePump 写泵：单 goroutine 串行写 WS，天然避免并发写冲突。
func (sess *muxSession) writePump() {
	for {
		select {
		case <-sess.die:
			return
		case frame := <-sess.writeCh:
			sess.ws.SetWriteDeadline(time.Now().Add(muxWriteIdle))
			if err := sess.ws.WriteMessage(websocket.BinaryMessage, frame); err != nil {
				sess.shutdown(err)
				return
			}
		}
	}
}

// pingLoop 保活。WriteControl 可与 writePump 的 WriteMessage 并发调用。
// pong 由读泵的 ReadMessage 自动处理。
func (sess *muxSession) pingLoop() {
	ticker := time.NewTicker(muxPingEvery)
	defer ticker.Stop()
	for {
		select {
		case <-sess.die:
			return
		case <-ticker.C:
			if err := sess.ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second)); err != nil {
				sess.shutdown(err)
				return
			}
		}
	}
}

// ============================================================
// muxSessionPool —— 会话池
// ============================================================

type muxSessionPool struct {
	mu       sync.Mutex
	sessions []*muxSession
	stop     chan struct{}
	stopOnce sync.Once
	wakeCh   chan struct{} // 容量释放通知（cap 1）

	rt *proxyRuntime // 所属运行时（测试构造的池可为 nil，仅拨号路径需要）
}

func newMuxSessionPool() *muxSessionPool {
	return &muxSessionPool{
		stop:   make(chan struct{}),
		wakeCh: make(chan struct{}, 1),
	}
}

func (p *muxSessionPool) wake() {
	if p == nil {
		return
	}
	select {
	case p.wakeCh <- struct{}{}:
	default:
	}
}

func (p *muxSessionPool) stopped() bool {
	if p == nil {
		return true
	}
	select {
	case <-p.stop:
		return true
	default:
		return false
	}
}

// dialSession 建立一条新的复用会话（复用既有 ECH+WS 拨号逻辑）。
// 测试构造的池没有关联运行时，不能拨号。
func (p *muxSessionPool) dialSession() (*muxSession, error) {
	if p.rt == nil {
		return nil, errors.New("mux: 会话池未关联运行时")
	}
	ws, err := p.rt.dialWebSocketWithECH(2)
	if err != nil {
		return nil, fmt.Errorf("mux: 拨号失败: %w", err)
	}
	return newMuxSession(ws, p), nil
}

// open 获取一条有余量的健康会话并打开流。
// 会话失效自动换会话重试一次；服务端明确拒绝则直接返回。
func (p *muxSessionPool) open(target string) (*muxStream, error) {
	if p == nil {
		return nil, errors.New("mux: 连接池未启动")
	}
	for range 2 {
		if p.stopped() {
			return nil, errors.New("mux: 连接池已停止")
		}
		sess, err := p.acquire()
		if err != nil {
			return nil, err
		}
		stream, err := sess.openStream(target)
		if err == nil {
			return stream, nil
		}
		if errors.Is(err, errMuxRefused) {
			return nil, err // 目标不可达，换会话无意义
		}
		sess.shutdown(err) // 会话疑似失效，丢弃并重试
	}
	return nil, errors.New("mux: 打开流失败")
}

// acquire 挑选流数最少且有余量的会话；没有则拨新会话；
// 达到会话上限且全部满载时等待流释放（最长 muxOpenTimeout）。
func (p *muxSessionPool) acquire() (*muxSession, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	deadline := time.Now().Add(muxOpenTimeout)
	for {
		alive := p.sessions[:0]
		for _, s := range p.sessions {
			if s.alive() {
				alive = append(alive, s)
			}
		}
		p.sessions = alive

		var best *muxSession
		for _, s := range p.sessions {
			if s.count() < muxStreamsPerSession {
				if best == nil || s.count() < best.count() {
					best = s
				}
			}
		}
		if best != nil {
			return best, nil
		}

		if len(p.sessions) < muxMaxSessions {
			p.mu.Unlock()
			sess, err := p.dialSession()
			p.mu.Lock()
			if err != nil {
				return nil, err
			}
			p.sessions = append(p.sessions, sess)
			return sess, nil
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, errMuxPoolEmpty
		}
		timer := time.NewTimer(remaining)
		select {
		case <-p.wakeCh:
			timer.Stop()
		case <-timer.C:
		case <-p.stop:
			timer.Stop()
			return nil, errors.New("mux: 连接池已停止")
		}
	}
}

// startMuxPool 启动会话池与保温循环（须在 prepareECH 成功后调用）。
func (r *proxyRuntime) startMuxPool() {
	r.muxPool = newMuxSessionPool()
	r.muxPool.rt = r
	go r.muxPool.loop()
	log.Printf("[MUX] 会话池已启动（单会话 ≤%d 流，最多 %d 会话）", muxStreamsPerSession, muxMaxSessions)
}

// stopMuxPool 停止会话池并关闭所有会话。
func (r *proxyRuntime) stopMuxPool() {
	p := r.muxPool
	if p == nil {
		return
	}
	r.muxPool = nil
	p.stopOnce.Do(func() { close(p.stop) })
	p.mu.Lock()
	sessions := p.sessions
	p.sessions = nil
	p.mu.Unlock()
	for _, s := range sessions {
		s.shutdown(nil)
	}
	log.Printf("[MUX] 会话池已停止")
}

// loop 低频保温：池空时预热 2 条让新连接尽量零握手；
// 存活会话利用率 ≥60% 时异步补拨 1 条，抢在流量洪峰前把容量备好。
func (p *muxSessionPool) loop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-ticker.C:
		}

		if p.stopped() {
			return
		}

		p.mu.Lock()
		alive := p.sessions[:0]
		used := 0
		for _, s := range p.sessions {
			if s.alive() {
				alive = append(alive, s)
				used += s.count()
			}
		}
		p.sessions = alive
		need := 0
		switch {
		case len(alive) == 0:
			need = 2
		case used*10 >= len(alive)*muxStreamsPerSession*6 && len(alive) < muxMaxSessions:
			need = 1
		}
		p.mu.Unlock()

		for range need {
			if p.stopped() {
				return
			}
			sess, err := p.dialSession()
			if err != nil {
				break
			}
			p.mu.Lock()
			if p.stopped() || len(p.sessions) >= muxMaxSessions {
				p.mu.Unlock()
				sess.shutdown(nil)
				break
			}
			p.sessions = append(p.sessions, sess)
			p.mu.Unlock()
		}
	}
}
