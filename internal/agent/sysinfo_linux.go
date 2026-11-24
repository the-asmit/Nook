//go:build linux

package agent

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// memory reads total and available memory from /proc/meminfo.
func memory() (total, available int64, err error) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, fmt.Errorf("read /proc/meminfo: %w", err)
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		kb, convErr := strconv.ParseInt(fields[1], 10, 64)
		if convErr != nil {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			total = kb * 1024
		case "MemAvailable:":
			available = kb * 1024
		}
	}
	if total == 0 {
		return 0, 0, errors.New("MemTotal missing from /proc/meminfo")
	}
	return total, available, nil
}

// loadAverage reads the one-minute load average.
func loadAverage() (float64, error) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, fmt.Errorf("read /proc/loadavg: %w", err)
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0, errors.New("empty /proc/loadavg")
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, fmt.Errorf("parse /proc/loadavg: %w", err)
	}
	return v, nil
}

// disk reports total and free bytes of the file system holding path.
func disk(path string) (total, free int64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, fmt.Errorf("statfs %s: %w", path, err)
	}
	bsize := int64(st.Bsize)                                       //nolint:unconvert // Bsize's type differs between architectures.
	return int64(st.Blocks) * bsize, int64(st.Bavail) * bsize, nil //nolint:gosec // G115: block counts fit in int64.
}
