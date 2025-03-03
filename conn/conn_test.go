package conn

import "testing"

func TestListenUDP(t *testing.T) {
	for _, lcc := range []struct {
		name string
		lc   ListenConfig
	}{
		{"DefaultUDPServerListenConfig", DefaultUDPServerListenConfig},
		{"DefaultUDPClientListenConfig", DefaultUDPClientListenConfig},
	} {
		t.Run(lcc.name, func(t *testing.T) {
			for _, nac := range []struct {
				name    string
				network string
				address string
			}{
				{"udp+zero", "udp", ""},
				{"udp+loopback4", "udp4", "127.0.0.1:"},
				{"udp+loopback6", "udp6", "[::1]:"},
				{"udp4+zero", "udp4", ""},
				{"udp4+loopback4", "udp4", "127.0.0.1:"},
				{"udp6+zero", "udp6", ""},
				{"udp6+loopback6", "udp6", "[::1]:"},
			} {
				t.Run(nac.name, func(t *testing.T) {
					uc, _, err := lcc.lc.ListenUDP(t.Context(), nac.network, nac.address)
					if err != nil {
						t.Fatal(err)
					}
					_ = uc.Close()
				})
			}
		})
	}
}
