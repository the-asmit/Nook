package config

import "testing"

func TestIsInternalHost(t *testing.T) {
	cases := map[string]bool{
		"/var/run/postgresql": true,
		"127.0.0.1":           true,
		"::1":                 true,
		"[::1]":               true,
		"localhost":           true,
		"10.1.2.3":            true,
		"172.16.0.5":          true,
		"192.168.1.20":        true,
		"fd00::1":             true,
		"postgres":            true,
		"redis_1":             true,
		"":                    false,
		"8.8.8.8":             false,
		"172.32.0.1":          false,
		"db.example.com":      false,
		"db.internal":         false,
		"-bad":                false,
		"169.254.1.1":         false,
	}
	for host, want := range cases {
		if got := IsInternalHost(host); got != want {
			t.Errorf("IsInternalHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestIsLoopbackHost(t *testing.T) {
	for host, want := range map[string]bool{"localhost": true, "LOCALHOST": true, "127.0.0.2": true, "[::1]": true, "10.0.0.1": false, "example.com": false} {
		if got := IsLoopbackHost(host); got != want {
			t.Errorf("IsLoopbackHost(%q) = %v, want %v", host, got, want)
		}
	}
}
