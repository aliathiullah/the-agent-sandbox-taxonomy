// Platform-specific syscall wrappers for Linux.
//go:build linux

package l1

import "syscall"

func tryMount(source, target, fstype string) error {
	return syscall.Mount(source, target, fstype, 0, "")
}

func tryUnmount(target string) error {
	return syscall.Unmount(target, 0)
}

func tryPtraceAttach(pid int) error {
	return syscall.PtraceAttach(pid)
}

func tryPtraceDetach(pid int) error {
	return syscall.PtraceDetach(pid)
}
