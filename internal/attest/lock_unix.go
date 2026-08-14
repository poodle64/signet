//go:build !windows

// lock_unix.go: the cross-process single-flight lock guarding a cold or expired
// bearer cache.
//
// The lock is taken on the CACHE FILE ITSELF, not a companion lockfile: key
// custody permits exactly two on-disk artefacts (`20-key-custody.md` §3), and a
// third one — even an empty one — invites the reader to wonder which rule it
// sits under. flock is advisory and costs nothing here.
package attest

import (
	"os"
	"syscall"
)

// lockCache blocks until this process holds the cache file's lock, returning
// the release function. Every failure path returns a no-op release rather than
// an error: the lock only ever saves a redundant attestation, so failing to get
// one must never stop a caller getting its bearer.
func lockCache(brokerURL, fingerprint string) func() {
	path, err := cachePath(brokerURL, fingerprint)
	if err != nil {
		return func() {}
	}
	// O_CREATE: on a cold start there is no cache file yet, and the waiters
	// still need something to serialise on. saveCache replaces this inode by
	// rename, which is why the holder writes BEFORE releasing — a waiter that
	// acquires the old inode's lock then re-reads the path sees the new file.
	f, err := os.OpenFile(path, os.O_RDONLY|os.O_CREATE, 0o600)
	if err != nil {
		return func() {}
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return func() {}
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}
}
