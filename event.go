package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type event struct {
	PIDTGID uint64
	Inode   uint64
	Major   uint32
	Minor   uint32
	Comm    [16]byte
}

func decodeEvent(raw []byte) (event, error) {
	var e event
	if len(raw) != binary.Size(e) {
		return e, fmt.Errorf("invalid event length: %d", len(raw))
	}
	err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e)
	return e, err
}

type fileIdentity struct {
	Inode, Links uint64
	Major, Minor uint32
	Regular      bool
	RootOwned    bool
	Blocks       int64
}

func matchVictim(e event, f fileIdentity) error {
	if string(bytes.TrimRight(e.Comm[:], "\x00")) != "dd" {
		return fmt.Errorf("process is not dd")
	}
	if e.Inode == 0 || e.Inode != f.Inode || e.Major != f.Major || e.Minor != f.Minor {
		return fmt.Errorf("event does not identify fill.bin on this filesystem")
	}
	if !f.Regular || !f.RootOwned || f.Links != 1 || f.Blocks <= 0 {
		return fmt.Errorf("fill.bin must be a root-owned regular file with one link and allocated blocks")
	}
	return nil
}
