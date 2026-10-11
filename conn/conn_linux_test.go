package conn

import "testing"

func TestKernelVersion(t *testing.T) {
	major, minor := kernelVersion()
	t.Logf("Kernel version: %d.%d", major, minor)
}

func TestParseUtsnameRelease(t *testing.T) {
	for _, c := range [...]struct {
		name      string
		release   [65]byte
		wantMajor int
		wantMinor int
	}{
		{
			name:      "7.2.9-arch1-1",
			release:   [65]byte{'7', '.', '2', '.', '9', '-', 'a', 'r', 'c', 'h', '1', '-', '1'},
			wantMajor: 7,
			wantMinor: 2,
		},
		{
			name:      "6.19.14-arch1-1",
			release:   [65]byte{'6', '.', '1', '9', '.', '1', '4', '-', 'a', 'r', 'c', 'h', '1', '-', '1'},
			wantMajor: 6,
			wantMinor: 19,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			major, minor := parseUtsnameRelease(c.release)
			if major != c.wantMajor || minor != c.wantMinor {
				t.Errorf("parseUtsnameRelease() = %d.%d; want %d.%d", major, minor, c.wantMajor, c.wantMinor)
			}
		})
	}
}
