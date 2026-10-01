//go:build !windows

package auth

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

// ownedSafely refuses a cache file another user could have written: group-
// or world-writable, or owned by another uid.
func ownedSafely(info fs.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("the file's owner cannot be read")
	}
	return cacheFileProblem(info.Mode(), int(st.Uid), os.Getuid())
}
