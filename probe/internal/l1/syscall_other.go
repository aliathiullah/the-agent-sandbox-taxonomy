// Platform-specific syscall stubs for non-Linux.
//go:build !linux

package l1

import "syscall"

func tryMount(source, target, fstype string) error {
	return syscall.ENOSYS
}

func tryUnmount(target string) error {
	return syscall.ENOSYS
}

func tryPtraceAttach(pid int) error {
	return syscall.ENOSYS
}

func tryPtraceDetach(pid int) error {
	return syscall.ENOSYS
}
