package log

import (
	"bytes"
	"strings"
	"sync"
	"testing"

	logrus "github.com/sirupsen/logrus"
)

func TestLevelDefaultAndFiltering(t *testing.T) {
	previous := Level()
	defer SetLevel(previous)
	if previous != INFO {
		t.Fatalf("default level = %v, want info", previous)
	}
	var output bytes.Buffer
	previousOutput := logrus.StandardLogger().Out
	logrus.SetOutput(&output)
	defer logrus.SetOutput(previousOutput)
	for _, threshold := range []LogLevel{DEBUG, INFO, WARNING, ERROR, SILENT} {
		SetLevel(threshold)
		if Level() != threshold {
			t.Fatalf("level = %v, want %v", Level(), threshold)
		}
		output.Reset()
		for _, severity := range []LogLevel{DEBUG, INFO, WARNING, ERROR} {
			print(Event{LogLevel: severity, Payload: "payload-" + severity.String()})
		}
		for _, severity := range []LogLevel{DEBUG, INFO, WARNING, ERROR} {
			if got := strings.Contains(output.String(), "payload-"+severity.String()); got != (severity >= threshold) {
				t.Errorf("threshold %v emitted %v = %v", threshold, severity, got)
			}
		}
	}
}

func TestLevelConcurrentReadersAndWriter(t *testing.T) {
	previous := Level()
	defer SetLevel(previous)
	var workers sync.WaitGroup
	workers.Add(2)
	start := make(chan struct{})
	go func() {
		defer workers.Done()
		<-start
		for i := 0; i < 20000; i++ {
			SetLevel(INFO)
			SetLevel(SILENT)
		}
	}()
	go func() {
		defer workers.Done()
		<-start
		for i := 0; i < 20000; i++ {
			if current := Level(); current != INFO && current != SILENT {
				t.Errorf("unexpected level %v", current)
			}
			Debugln("suppressed concurrent log")
		}
	}()
	close(start)
	workers.Wait()
}
