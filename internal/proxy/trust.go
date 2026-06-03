package proxy

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// Privileged trust-store operations resolve their helper binaries from a fixed
// set of trusted system directories rather than $PATH. These functions run with
// elevated privileges (sudo / Administrator); trusting $PATH would let a planted
// `cp`/`security`/`update-ca-certificates` execute as root (CWE-426).

// linuxCADest is the fixed destination for the trusted CA on Debian/Ubuntu.
const linuxCADest = "/usr/local/share/ca-certificates/phoenix-firewall-ca.crt"

// trustedBinDirs are the only directories searched for privileged helper
// binaries on Unix, in priority order.
var trustedBinDirs = []string{"/usr/sbin", "/sbin", "/usr/bin", "/bin"}

// resolveTrustedBinary returns the absolute path of name within trustedBinDirs,
// or an error if it is not found. It never consults $PATH.
func resolveTrustedBinary(name string) (string, error) {
	for _, dir := range trustedBinDirs {
		p := filepath.Join(dir, name)
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s not found in trusted directories %v", name, trustedBinDirs)
}

// copyFile copies src to dst, creating dst with 0644 (a public CA cert).
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// InjectCA installs the CA certificate into the system trust store.
// Requires elevated privileges on most platforms.
func InjectCA(certPath string) error {
	switch runtime.GOOS {
	case "darwin":
		return injectDarwin(certPath)
	case "linux":
		return injectLinux(certPath)
	case "windows":
		return injectWindows(certPath)
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// RemoveCA removes the CA certificate from the system trust store.
func RemoveCA(certPath string) error {
	switch runtime.GOOS {
	case "darwin":
		return removeDarwin(certPath)
	case "linux":
		return removeLinux(certPath)
	case "windows":
		return removeWindows(certPath)
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

func injectDarwin(certPath string) error {
	// security lives at a fixed absolute path on macOS.
	cmd := exec.Command("/usr/bin/security", "add-trusted-cert", "-d", "-r", "trustRoot",
		"-k", "/Library/Keychains/System.keychain", certPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		printManualInstructions("macOS", certPath)
		return fmt.Errorf("macOS trust injection failed (requires sudo): %s: %w", string(out), err)
	}
	fmt.Println("CA certificate trusted on macOS.")
	return nil
}

func injectLinux(certPath string) error {
	updateBin, err := resolveTrustedBinary("update-ca-certificates")
	if err != nil {
		printManualInstructions("Linux", certPath)
		return fmt.Errorf("locate update-ca-certificates: %w", err)
	}
	// Copy in-process rather than shelling out to `cp` (no $PATH dependency).
	if err := copyFile(certPath, linuxCADest); err != nil {
		printManualInstructions("Linux", certPath)
		return fmt.Errorf("copy CA cert to %s failed (requires sudo): %w", linuxCADest, err)
	}
	if out, err := exec.Command(updateBin).CombinedOutput(); err != nil {
		return fmt.Errorf("update-ca-certificates failed: %s: %w", string(out), err)
	}
	fmt.Println("CA certificate trusted on Linux.")
	return nil
}

func injectWindows(certPath string) error {
	cmd := exec.Command(windowsCertutil(), "-addstore", "-user", "Root", certPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		printManualInstructions("Windows", certPath)
		return fmt.Errorf("certutil failed: %s: %w", string(out), err)
	}
	fmt.Println("CA certificate trusted on Windows.")
	return nil
}

func removeDarwin(certPath string) error {
	cmd := exec.Command("/usr/bin/security", "remove-trusted-cert", "-d", certPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("macOS trust removal failed: %s: %w", string(out), err)
	}
	return nil
}

func removeLinux(_ string) error {
	updateBin, err := resolveTrustedBinary("update-ca-certificates")
	if err != nil {
		return fmt.Errorf("locate update-ca-certificates: %w", err)
	}
	if err := os.Remove(linuxCADest); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove CA cert failed: %w", err)
	}
	if out, err := exec.Command(updateBin, "--fresh").CombinedOutput(); err != nil {
		return fmt.Errorf("update-ca-certificates failed: %s: %w", string(out), err)
	}
	return nil
}

func removeWindows(certPath string) error {
	cmd := exec.Command(windowsCertutil(), "-delstore", "-user", "Root", certPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("certutil removal failed: %s: %w", string(out), err)
	}
	return nil
}

// windowsCertutil returns the absolute path to certutil.exe under the system
// root, falling back to the conventional location if %SystemRoot% is unset.
func windowsCertutil() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", "certutil.exe")
}

func printManualInstructions(platform, certPath string) {
	fmt.Println("\n=== Manual CA Trust Instructions ===")
	fmt.Printf("Platform: %s\n", platform)
	fmt.Printf("CA cert:  %s\n\n", certPath)
	switch platform {
	case "macOS":
		fmt.Println("Run with sudo:")
		fmt.Printf("  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s\n", certPath)
	case "Linux":
		fmt.Println("Run with sudo:")
		fmt.Printf("  sudo cp %s %s\n", certPath, linuxCADest)
		fmt.Println("  sudo update-ca-certificates")
	case "Windows":
		fmt.Println("Run as Administrator:")
		fmt.Printf("  certutil -addstore -user Root %s\n", certPath)
	}
	fmt.Println("====================================")
}
