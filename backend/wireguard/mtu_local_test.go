package wireguard

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestLocalMTUValidation(t *testing.T) {
	for _, v := range []int{576, 1280, 1320, 1420, 9000} {
		c, err := NewConfig(fmt.Sprintf(`{"mtu":%d}`, v))
		if err != nil || c.MTU == nil || *c.MTU != v {
			t.Fatalf("valid %d: %v", v, err)
		}
	}
	for _, v := range []string{"0", "575", "9001", "-1", "1320.5", `"1320"`, "true", "[]", "{}"} {
		if _, err := NewConfig(`{"mtu":` + v + `}`); err == nil {
			t.Fatalf("accepted %s", v)
		}
	}
	c, err := NewConfig(`{}`)
	if err != nil || c.MTU != nil {
		t.Fatal("missing MTU must preserve default")
	}
}

func TestLocalMTUFailure(t *testing.T) {
	target := 1320
	link := &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: "wg-mtu", MTU: 1420}}
	m := &Manager{client: &fakeWGClient{}, defaultMTU: 1420, nl: mockNetlinkOps{linkByName: func(string) (netlink.Link, error) { return link, nil }}, setLinkMTU: func(netlink.Link, int) error { return syscall.EPERM }}
	if err := m.applyConfig(wgtypes.Config{}, &target); !errors.Is(err, syscall.EPERM) {
		t.Fatalf("wrong error: %v", err)
	}
	if m.mtuManaged {
		t.Fatal("failed update committed state")
	}
}

func TestLocalMTULive(t *testing.T) {
	if os.Getenv("NODE_MTU_LIVE") != "1" {
		t.Skip("requires Linux CAP_NET_ADMIN")
	}
	name := fmt.Sprintf("mtu%d", os.Getpid())
	m, err := NewManager(name)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	mtu := 1320
	if err = m.initializeWithPeers(key, 0, []string{"10.251.251.1/24"}, nil, &mtu); err != nil {
		t.Fatal(err)
	}
	check := func(want int) {
		t.Helper()
		link, e := netlink.LinkByName(name)
		if e != nil {
			t.Fatal(e)
		}
		if link.Attrs().MTU != want {
			t.Fatalf("MTU %d want %d", link.Attrs().MTU, want)
		}
	}
	check(1320)
	mtu = 1280
	if err = m.applyConfig(wgtypes.Config{}, &mtu); err != nil {
		t.Fatal(err)
	}
	check(1280)
	mtu = 575
	if err = m.applyConfig(wgtypes.Config{}, &mtu); err == nil {
		t.Fatal("invalid MTU accepted")
	}
	check(1280)
	if err = m.applyConfig(wgtypes.Config{}, nil); err != nil {
		t.Fatal(err)
	}
	check(m.defaultMTU)
	if err = m.initializeWithPeers(key, 0, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	check(m.defaultMTU)
	t.Logf("verified create, update, invalid value, reset and default (MTU=%d)", m.defaultMTU)
}
