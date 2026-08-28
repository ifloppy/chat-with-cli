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
