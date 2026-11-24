//go:build !linux

package agent

import "errors"

// errUnsupported: nook-agent runs on Linux worker nodes only. This file
// lets the rest of the module build and be tested on other systems.
var errUnsupported = errors.New("nook-agent supports Linux only")

func memory() (total, available int64, err error) { return 0, 0, errUnsupported }

func loadAverage() (float64, error) { return 0, errUnsupported }

func disk(string) (total, free int64, err error) { return 0, 0, errUnsupported }
