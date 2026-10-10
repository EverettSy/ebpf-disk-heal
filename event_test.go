package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestEventABI(t *testing.T) {
	want := event{PIDTGID: 123 << 32, Inode: 456, Major: 7, Minor: 2}
	copy(want.Comm[:], "dd")
	var raw bytes.Buffer
	if err := binary.Write(&raw, binary.LittleEndian, want); err != nil {
		t.Fatal(err)
	}
	if raw.Len() != 40 {
		t.Fatalf("ABI size = %d", raw.Len())
	}
	got, err := decodeEvent(raw.Bytes())
	if err != nil || got != want {
		t.Fatalf("decode = %+v, %v", got, err)
	}
	for _, size := range []int{0, 39, 41} {
		if _, err := decodeEvent(make([]byte, size)); err == nil {
			t.Fatalf("accepted event length %d", size)
		}
	}
}

func TestVictimGuard(t *testing.T) {
	e := event{Inode: 456, Major: 7, Minor: 2}
	copy(e.Comm[:], "dd")
	f := fileIdentity{Inode: 456, Major: 7, Minor: 2, Links: 1, Regular: true, RootOwned: true, Blocks: 100}
	if err := matchVictim(e, f); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		edit func(*event, *fileIdentity)
	}{
		{"other process", func(e *event, _ *fileIdentity) { e.Comm[0] = 'x' }},
		{"other device", func(e *event, _ *fileIdentity) { e.Minor++ }},
		{"replaced file", func(_ *event, f *fileIdentity) { f.Inode++ }},
		{"missing inode", func(e *event, _ *fileIdentity) { e.Inode = 0 }},
		{"symlink", func(_ *event, f *fileIdentity) { f.Regular = false }},
		{"hardlink", func(_ *event, f *fileIdentity) { f.Links++ }},
		{"untrusted owner", func(_ *event, f *fileIdentity) { f.RootOwned = false }},
		{"empty file", func(_ *event, f *fileIdentity) { f.Blocks = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e2, f2 := e, f
			tc.edit(&e2, &f2)
			if err := matchVictim(e2, f2); err == nil {
				t.Fatal("unsafe cleanup accepted")
			}
		})
	}
}
