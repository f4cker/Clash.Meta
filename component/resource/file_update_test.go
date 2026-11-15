package resource

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/metacubex/mihomo/common/utils"
)

type controlledFileVehicle struct {
	*FileVehicle
	read  func() ([]byte, error)
	write func([]byte) error
}

func (v *controlledFileVehicle) Read(_ context.Context, _ utils.HashType) ([]byte, utils.HashType, error) {
	data, err := v.read()
	return data, utils.MakeHash(data), err
}
func (v *controlledFileVehicle) Write(data []byte) error { return v.write(data) }

func TestFileFetcherSerializesReadThroughPublication(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	data := []byte("old")
	v := &controlledFileVehicle{FileVehicle: NewFileVehicle(filepath.Join(t.TempDir(), "source"))}
	v.read = func() ([]byte, error) { captured := bytes.Clone(data); close(entered); <-release; return captured, nil }
	v.write = func(next []byte) error { data = bytes.Clone(next); return nil }
	var published []string
	fetcher := NewFetcher("source", 0, v, nil, func(data []byte) (string, error) { return string(data), nil }, func(value string) { published = append(published, value) })
	defer fetcher.Close()
	done := make(chan error, 1)
	go func() { _, _, err := fetcher.Update(); done <- err }()
	<-entered
	if fetcher.loadBufMutex.TryLock() {
		fetcher.loadBufMutex.Unlock()
		close(release)
		<-done
		t.Fatal("FILE read was outside publication mutex")
	}
	updated := make(chan error, 1)
	go func() { _, _, err := fetcher.SideUpdate([]byte("new")); updated <- err }()
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := <-updated; err != nil {
		t.Fatal(err)
	}
	if string(data) != "new" || len(published) != 2 || published[0] != "old" || published[1] != "new" {
		t.Fatalf("data=%q published=%v", data, published)
	}
}

func TestFileFetcherFailuresRetainFileHashAndPublishedValue(t *testing.T) {
	for _, failure := range []string{"read", "parse", "write"} {
		t.Run(failure, func(t *testing.T) {
			data := []byte("old")
			fail := false
			v := &controlledFileVehicle{FileVehicle: NewFileVehicle(filepath.Join(t.TempDir(), "source"))}
			v.read = func() ([]byte, error) {
				if fail && failure == "read" {
					return nil, errors.New("read failure")
				}
				return bytes.Clone(data), nil
			}
			v.write = func(next []byte) error {
				if fail && failure == "write" {
					return errors.New("write failure")
				}
				data = bytes.Clone(next)
				return nil
			}
			published := ""
			fetcher := NewFetcher("source", 0, v, nil, func(data []byte) (string, error) {
				if fail && failure == "parse" {
					return "", errors.New("parse failure")
				}
				return string(data), nil
			}, func(value string) { published = value })
			defer fetcher.Close()
			if _, _, err := fetcher.Update(); err != nil {
				t.Fatal(err)
			}
			oldHash := fetcher.hash
			fail = true
			var err error
			if failure == "read" {
				_, _, err = fetcher.Update()
			} else {
				_, _, err = fetcher.SideUpdate([]byte("new"))
			}
			if err == nil || published != "old" || string(data) != "old" || !fetcher.hash.Equal(oldHash) {
				t.Fatalf("error=%v data=%q runtime=%q", err, data, published)
			}
		})
	}
}

func TestFileVehicleAtomicReplacePreservesMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source.yaml")
	if err := os.WriteFile(path, []byte("old"), 0640); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	oldHandle, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer oldHandle.Close()
	if err := NewFileVehicle(path).Write([]byte("new")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "new" {
		t.Fatalf("new path=%q error=%v", data, err)
	}
	if runtime.GOOS != "windows" {
		old := make([]byte, 3)
		if _, err := oldHandle.Read(old); err != nil || string(old) != "old" {
			t.Fatalf("old inode was truncated: %q %v", old, err)
		}
		after, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		first, _ := tar.FileInfoHeader(fileOwnerInfo{before}, "")
		last, _ := tar.FileInfoHeader(fileOwnerInfo{after}, "")
		if before.Mode() != after.Mode() || first.Uid != last.Uid || first.Gid != last.Gid {
			t.Fatal("owner or mode changed")
		}
	}
	files, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(files) != 1 {
		t.Fatalf("staging files leaked: %v %v", files, err)
	}
}

func TestFileVehicleRejectedWriteRetainsDestination(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "original")
	if err := os.WriteFile(target, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := NewFileVehicle(link).Write([]byte("new")); err == nil {
		t.Fatal("symlink accepted")
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "old" {
		t.Fatalf("failed write changed destination: %q %v", data, err)
	}
	if err := NewFileVehicle(dir).Write([]byte("new")); err == nil {
		t.Fatal("directory accepted")
	}
}
