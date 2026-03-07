// Package l6 provides a Linux-specific syscall wrapper for init_module.
//go:build linux

package l6

import "syscall"

func init_module_errno() syscall.Errno {
	_, _, e := syscall.Syscall(syscall.SYS_INIT_MODULE, 0, 0, 0)
	return e
}

func tryReboot(cmd int) error {
	return syscall.Reboot(cmd)
}

func trySethostname(name []byte) error {
	return syscall.Sethostname(name)
}
