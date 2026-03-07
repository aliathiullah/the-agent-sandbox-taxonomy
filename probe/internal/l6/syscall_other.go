// Package l6 provides a no-op init_module stub for non-Linux platforms.
//go:build !linux

package l6

import "syscall"

func init_module_errno() syscall.Errno {
	return syscall.ENOSYS
}

func tryReboot(cmd int) error {
	return syscall.ENOSYS
}

func trySethostname(name []byte) error {
	return syscall.ENOSYS
}
