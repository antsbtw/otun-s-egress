package egress

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// blackholeProxy forwards TCP both ways until blackholed; after that it keeps
// the sockets open but silently drops every byte — the shape of a half-dead
// path where neither side sees a FIN/RST.
type blackholeProxy struct {
	ln        net.Listener
	target    string
	blackhole atomic.Bool
	wg        sync.WaitGroup
}

func newBlackholeProxy(t *testing.T, target string) *blackholeProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &blackholeProxy{ln: ln, target: target}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			up, err := net.Dial("tcp", target)
			if err != nil {
				c.Close()
				continue
			}
			pipe := func(dst, src net.Conn) {
				defer p.wg.Done()
				buf := make([]byte, 32*1024)
				for {
					n, err := src.Read(buf)
					if err != nil {
						dst.Close()
						src.Close()
						return
					}
					if p.blackhole.Load() {
						continue
					}
					if _, err := dst.Write(buf[:n]); err != nil {
						return
					}
				}
			}
			p.wg.Add(2)
			go pipe(up, c)
			go pipe(c, up)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return p
}

// 2026-09-29 regression: a long-lived request (the realm event stream) on a
// half-dead HTTP/2 connection must be torn down by the PING health check
// instead of blocking until the kernel TCP timeout.
func TestRendezvousHTTPClientDetectsDeadConnection(t *testing.T) {
	oldSend, oldPing := rendezvousSendPingTimeout, rendezvousPingTimeout
	rendezvousSendPingTimeout, rendezvousPingTimeout = 300*time.Millisecond, 300*time.Millisecond
	t.Cleanup(func() { rendezvousSendPingTimeout, rendezvousPingTimeout = oldSend, oldPing })

	release := make(chan struct{})
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		select { // event stream: headers, then silence
		case <-release:
		case <-r.Context().Done():
		}
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	defer close(release)

	proxy := newBlackholeProxy(t, srv.Listener.Addr().String())
	hc := rendezvousHTTPClient(true) // self-signed test cert
	url := "https://" + proxy.ln.Addr().String() + "/events"

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Fatalf("proto = %s, want HTTP/2 (pings only exist on h2)", resp.Proto)
	}

	proxy.blackhole.Store(true)
	start := time.Now()
	readDone := make(chan error, 1)
	go func() {
		_, err := io.ReadAll(resp.Body)
		readDone <- err
	}()
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("stream ended cleanly; want connection-lost error")
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Fatalf("dead connection detected after %v", elapsed)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("event stream still blocked 10s after the path went dead; HTTP/2 PING health check not active")
	}
}
