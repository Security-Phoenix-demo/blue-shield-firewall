package endpoint

import "testing"

func TestFromHostMACDerivesStableUUID(t *testing.T) {
	id := FromHostMAC("Build-Host-01", "AA:BB:CC:DD:EE:FF", []string{"aa:bb:cc:dd:ee:ff"}, "alice", "501", "/Users/alice")

	if id.DeviceID != "72460ba3-1292-5d86-958f-73e46058a088" {
		t.Fatalf("unexpected device id: %s", id.DeviceID)
	}
	if id.IDSource != "hostname_mac" {
		t.Fatalf("unexpected id source: %s", id.IDSource)
	}
}

func TestMetadataIncludesEndpointContext(t *testing.T) {
	id := FromHostMAC("host-a", "00:11:22:33:44:55", []string{"00:11:22:33:44:55"}, "alice", "501", "/Users/alice")
	metadata := id.Metadata("shim")

	if metadata["hostname"] != "host-a" {
		t.Fatalf("hostname metadata missing: %#v", metadata)
	}
	if metadata["primary_mac"] != "00:11:22:33:44:55" {
		t.Fatalf("primary_mac metadata missing: %#v", metadata)
	}
	if metadata["logged_in_user"] != "alice" {
		t.Fatalf("logged_in_user metadata missing: %#v", metadata)
	}
	if metadata["collector"] != "shim" {
		t.Fatalf("collector metadata missing: %#v", metadata)
	}
}
