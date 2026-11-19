package adapter

import (
	"context"
	"errors"
	"math"
	"sync"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

type offlineHistoryAdapter struct {
	C.ProxyAdapter
}

func (offlineHistoryAdapter) Name() string { return "offline-history" }

func (offlineHistoryAdapter) DialContext(context.Context, *C.Metadata) (C.Conn, error) {
	return nil, errors.New("offline history test")
}

func TestProxyHistoryConcurrentURLTest(t *testing.T) {
	proxy := NewProxy(offlineHistoryAdapter{})
	const url = "http://history.invalid/probe"
	_, _ = proxy.URLTest(context.Background(), url, nil)
	var workers sync.WaitGroup
	workers.Add(2)
	start := make(chan struct{})
	go func() {
		defer workers.Done()
		<-start
		for i := 0; i < 10000; i++ {
			_, _ = proxy.URLTest(context.Background(), url, nil)
		}
	}()
	go func() {
		defer workers.Done()
		<-start
		for i := 0; i < 10000; i++ {
			if delay := proxy.LastDelayForTestUrl(url); delay != math.MaxUint16 {
				t.Errorf("failed probe delay = %d", delay)
			}
		}
	}()
	close(start)
	workers.Wait()
	if got := len(proxy.DelayHistoryForTestUrl(url)); got != defaultHistoriesNum {
		t.Errorf("history length = %d, want %d", got, defaultHistoriesNum)
	}
}
