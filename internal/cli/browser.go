package cli

import (
	"context"
	"errors"
	"net/url"
	"os"
	"os/exec"
	"runtime"
)

// OpenBrowser asks the operating system to open u in the default browser.
// It is best effort: login also prints the URL for the user to open.
func OpenBrowser(u string) error {
	parsed, err := url.Parse(u)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		// Never hand anything but a web URL to an OS "open" command.
		return errors.New("not an http(s) URL")
	}
	var name string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		name, args = "open", []string{u}
	case "windows":
		name, args = "rundll32", []string{"url.dll,FileProtocolHandler", u}
	default:
		name, args = "xdg-open", []string{u}
		// Inside WSL, wslview (from wslu) opens the Windows browser.
		if os.Getenv("WSL_DISTRO_NAME") != "" {
			if _, err := exec.LookPath("wslview"); err == nil {
				name = "wslview"
			}
		}
	}
	if _, err := exec.LookPath(name); err != nil {
		return err
	}
	// Start without waiting: some openers block until the browser exits.
	cmd := exec.CommandContext(context.Background(), name, args...) //nolint:gosec // G204: fixed program, validated URL argument.
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
