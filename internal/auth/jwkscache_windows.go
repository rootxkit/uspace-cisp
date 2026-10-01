//go:build windows

package auth

import (
	"errors"
	"io/fs"
)

// ownedSafely on Windows checks only that the cache is a regular file.
// The group/world-writable and owner checks are skipped: Windows has no
// such mode bits (Go reports 0666 for any writable file) and file
// ownership lives in ACLs, which this check does not read. Production
// runs the Linux image, where the check applies.
func ownedSafely(info fs.FileInfo) error {
	if !info.Mode().IsRegular() {
		return errors.New("not a regular file")
	}
	return nil
}
