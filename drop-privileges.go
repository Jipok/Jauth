package main

import (
	"os"
	"os/user"
	"strconv"
	"syscall"
)

func dropPrivileges() error {
	u, err := user.Lookup("nobody")
	if err != nil {
		return err
	}

	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return err
	}

	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return err
	}

	// Chroot'ing before change uid/gid
	tmpDir, err := os.MkdirTemp("", "jauth-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	if err := syscall.Chroot(tmpDir); err != nil {
		return err
	}

	if err := os.Chdir("/"); err != nil {
		return err
	}

	if err := syscall.Setgid(gid); err != nil {
		return err
	}

	if err := syscall.Setuid(uid); err != nil {
		return err
	}

	return nil
}
