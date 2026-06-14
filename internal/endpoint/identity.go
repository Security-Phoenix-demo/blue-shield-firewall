package endpoint

import (
	"crypto/sha1"
	"encoding/hex"
	"net"
	"os"
	"os/user"
	"runtime"
	"sort"
	"strings"
)

var namespacePhoenixEndpoint = [16]byte{0x7f, 0x6b, 0x0f, 0x9f, 0x91, 0xbe, 0x4c, 0xf6, 0x9d, 0x67, 0x54, 0xb2, 0xf2, 0xc2, 0xf6, 0xda}

type Identity struct {
	DeviceID     string
	Hostname     string
	PrimaryMAC   string
	MACAddresses []string
	LoggedInUser string
	UserUID      string
	UserHomeDir  string
	OS           string
	Arch         string
	IDSource     string
}

func Collect() Identity {
	hostname := os.Getenv("PHOENIX_ENDPOINT_HOSTNAME")
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	macs := collectMACAddresses()
	if overrideMAC := strings.ToLower(strings.TrimSpace(os.Getenv("PHOENIX_ENDPOINT_MAC"))); overrideMAC != "" {
		macs = []string{overrideMAC}
	}
	primaryMAC := ""
	if len(macs) > 0 {
		primaryMAC = macs[0]
	}

	currentUser, _ := user.Current()
	loggedInUser := os.Getenv("PHOENIX_LOGGED_IN_USER")
	if loggedInUser == "" {
		loggedInUser = os.Getenv("USER")
	}
	if loggedInUser == "" {
		loggedInUser = os.Getenv("USERNAME")
	}
	uid := ""
	homeDir := ""
	if currentUser != nil {
		if loggedInUser == "" {
			loggedInUser = currentUser.Username
		}
		uid = currentUser.Uid
		homeDir = currentUser.HomeDir
	}

	return FromHostMAC(hostname, primaryMAC, macs, loggedInUser, uid, homeDir)
}

func FromHostMAC(hostname, primaryMAC string, macs []string, loggedInUser, uid, homeDir string) Identity {
	normalizedHost := strings.ToLower(strings.TrimSpace(hostname))
	normalizedMAC := strings.ToLower(strings.TrimSpace(primaryMAC))
	idSource := "hostname_mac"
	if normalizedMAC == "" {
		idSource = "hostname_no_mac"
	}
	name := normalizedHost + "|" + normalizedMAC

	return Identity{
		DeviceID:     uuidV5(name),
		Hostname:     hostname,
		PrimaryMAC:   primaryMAC,
		MACAddresses: append([]string{}, macs...),
		LoggedInUser: loggedInUser,
		UserUID:      uid,
		UserHomeDir:  homeDir,
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		IDSource:     idSource,
	}
}

func (i Identity) Metadata(collector string) map[string]interface{} {
	metadata := map[string]interface{}{
		"endpoint_id_source": i.IDSource,
		"hostname":           i.Hostname,
		"primary_mac":        i.PrimaryMAC,
		"mac_addresses":      i.MACAddresses,
		"logged_in_user":     i.LoggedInUser,
		"user_uid":           i.UserUID,
		"user_home_dir":      i.UserHomeDir,
		"os":                 i.OS,
		"arch":               i.Arch,
	}
	if collector != "" {
		metadata["collector"] = collector
	}
	return metadata
}

func collectMACAddresses() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	macs := []string{}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		mac := strings.ToLower(strings.TrimSpace(iface.HardwareAddr.String()))
		if mac == "" {
			continue
		}
		macs = append(macs, mac)
	}
	sort.Strings(macs)
	return macs
}

func uuidV5(name string) string {
	h := sha1.New()
	_, _ = h.Write(namespacePhoenixEndpoint[:])
	_, _ = h.Write([]byte(name))
	sum := h.Sum(nil)
	u := make([]byte, 16)
	copy(u, sum[:16])
	u[6] = (u[6] & 0x0f) | 0x50
	u[8] = (u[8] & 0x3f) | 0x80
	return hex.EncodeToString(u[0:4]) + "-" +
		hex.EncodeToString(u[4:6]) + "-" +
		hex.EncodeToString(u[6:8]) + "-" +
		hex.EncodeToString(u[8:10]) + "-" +
		hex.EncodeToString(u[10:16])
}
