//go:build !windows

package main

import "syscall"

func collectRusage() (*int64, *int64) {
	var rusage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &rusage); err != nil {
		return nil, nil
	}
	utime := rusage.Utime.Nano() / 1e6 // reduce resolution to avoid fingerprinting
	stime := rusage.Stime.Nano() / 1e6 // reduce resolution to avoid fingerprinting
	return &utime, &stime
}
