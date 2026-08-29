package protocol

import "testing"

func TestValidDeviceName(t *testing.T) {
	for _, name := range []string{"workstation", "dev-laptop", "dev_01", "host.example"} {
		if !ValidDeviceName(name) {
			t.Fatalf("valid name rejected: %q", name)
		}
	}
	for _, name := range []string{"", "../other", "a/b", "with space", "设备", string(make([]byte, 129))} {
		if ValidDeviceName(name) {
			t.Fatalf("invalid name accepted: %q", name)
		}
	}
}

func TestNormalizeDeviceIDCanonicalizesHexCase(t *testing.T) {
	got, ok := NormalizeDeviceID("ABCDEF0123456789ABCDEF0123456789")
	if !ok || got != "abcdef0123456789abcdef0123456789" {
		t.Fatalf("NormalizeDeviceID=%q ok=%v", got, ok)
	}
	if _, ok := NormalizeDeviceID("not-an-id"); ok {
		t.Fatal("invalid immutable ID normalized successfully")
	}
}
