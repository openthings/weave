package ipsec

// TODO
// * NAT traversal (ESP tunnel)
// * Implement Teardown
// * Fixes to vishvananda/netlink
// * Fixes to kernel

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"

	"github.com/coreos/go-iptables/iptables"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"

	"github.com/weaveworks/mesh"
)

type SPI uint32

const chainWeaveIPSec = "WEAVE-IPSEC"
const chainWeaveIPSecEgress = "WEAVE-IPSEC-EGRESS"
const skbMark = uint32(0x77766e74)

// API

func Reset() error {
	// TODO(mp) reset based on marker
	// TODO(mp) Select relevant fields

	if err := netlink.XfrmPolicyFlush(); err != nil {
		return errors.Wrap(err, "xfrm policy flush")
	}

	if err := netlink.XfrmStateFlush(netlink.XFRM_PROTO_ESP); err != nil {
		return errors.Wrap(err, "xfrm state flush")
	}

	if err := resetIPTables(); err != nil {
		return errors.Wrap(err, "reset ip tables")
	}

	return nil
}

func Setup(srcPeer, dstPeer mesh.PeerShortID, srcIP, dstIP net.IP, dstPort uint16, localKey, remoteKey []byte) error {
	outSPI, err := newSPI(srcPeer, dstPeer)
	if err != nil {
		return errors.Wrap(err, "new SPI")
	}
	inSPI, err := newSPI(dstPeer, srcPeer)
	if err != nil {
		return errors.Wrap(err, "new SPI")
	}

	// TODO(mp) make sure that keys are not logged

	if inSA, err := newXfrmState(dstIP, srcIP, inSPI, remoteKey); err == nil {
		if err := netlink.XfrmStateAdd(inSA); err != nil {
			return errors.Wrap(err, "xfrm state (in) add")
		}
	} else {
		return errors.Wrap(err, "new xfrm state")
	}

	if outSA, err := newXfrmState(srcIP, dstIP, outSPI, localKey); err == nil {
		if err := netlink.XfrmStateAdd(outSA); err != nil {
			return errors.Wrap(err, "xfrm state (out) add")
		}
	} else {
		return errors.Wrap(err, "new xfrm state")
	}

	outPolicy := newXfrmPolicy(srcIP, dstIP, outSPI)
	if err := netlink.XfrmPolicyAdd(outPolicy); err != nil {
		return errors.Wrap(err, "xfrm policy add")
	}

	if err := ensureIPTablesRule(srcIP, dstIP, dstPort); err != nil {
		return errors.Wrap(err, "ensure iptables")
	}

	return nil
}

// Helpers

// | 0.. SRC_PEER | 0.. DST_PEER |
func newSPI(srcPeer, dstPeer mesh.PeerShortID) (SPI, error) {
	var spi SPI

	if mesh.PeerShortIDBits > 16 { // should not happen
		return 0, fmt.Errorf("PeerShortID too long")
	}

	// TODO(mp) Fill the free space (8 bits) with RND
	spi = SPI(uint32(srcPeer)<<16 | uint32(dstPeer))

	return spi, nil
}

func newXfrmState(srcIP, dstIP net.IP, spi SPI, key []byte) (*netlink.XfrmState, error) {
	if len(key) != 36 {
		return nil, fmt.Errorf("key should be 36 bytes long")
	}

	return &netlink.XfrmState{
		Src:   srcIP,
		Dst:   dstIP,
		Proto: netlink.XFRM_PROTO_ESP, // TODO(mp) s/Proto/XfrmProto
		Mode:  netlink.XFRM_MODE_TRANSPORT,
		Spi:   int(spi), // TODO(mp) s/int/uint32
		Aead: &netlink.XfrmStateAlgo{
			Name:   "rfc4106(gcm(aes))",
			Key:    key,
			ICVLen: 128,
		},
	}, nil
}

func newXfrmPolicy(srcIP, dstIP net.IP, spi SPI) *netlink.XfrmPolicy {
	ipMask := []byte{0xff, 0xff, 0xff, 0xff} // /32

	return &netlink.XfrmPolicy{
		Src:   &net.IPNet{IP: srcIP, Mask: ipMask},
		Dst:   &net.IPNet{IP: dstIP, Mask: ipMask},
		Proto: syscall.IPPROTO_UDP,
		Dir:   netlink.XFRM_DIR_OUT,
		Mark: &netlink.XfrmMark{
			Value: skbMark,
		},
		Tmpls: []netlink.XfrmPolicyTmpl{
			{
				Src:   srcIP,
				Dst:   dstIP,
				Proto: netlink.XFRM_PROTO_ESP,
				Mode:  netlink.XFRM_MODE_TRANSPORT,
				Spi:   int(spi),
			},
		},
	}
}

func ensureIPTablesRule(srcIP, dstIP net.IP, dstPort uint16) error {
	ipt, err := iptables.New()
	if err != nil {
		return errors.Wrap(err, "iptables.New")
	}

	table := "mangle"
	chain := chainWeaveIPSecEgress
	rules := []string{"-j", chainWeaveIPSec, "-p", "udp", "-s", srcIP.String(),
		"-d", dstIP.String(), "--dport", strconv.FormatUint(uint64(dstPort), 10)}

	if err := ipt.Append(table, chain, rules...); err != nil {
		return errors.Wrap(err, "ipt.Append")
	}

	return nil
}

func resetIPTables() error {
	ipt, err := iptables.New()
	if err != nil {
		return errors.Wrap(err, "iptables.New")
	}

	ipt.Delete("mangle", "OUTPUT", "-j", "WEAVE-IPSEC-EGRESS")

	if err := resetChain(ipt, "mangle", chainWeaveIPSecEgress); err != nil {
		return errors.Wrap(err, "resetChain")
	}
	if err := resetChain(ipt, "mangle", chainWeaveIPSec); err != nil {
		return errors.Wrap(err, "resetChain")
	}

	// TODO(mp) create if does not exist
	if err := ipt.Append("mangle", "OUTPUT", "-j", chainWeaveIPSecEgress); err != nil {
		return errors.Wrap(err, "foobar")
	}

	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, skbMark)
	if err := ipt.Append("mangle", chainWeaveIPSec, "-j", "MARK",
		"--set-mark", "0x"+hex.EncodeToString(b)); err != nil {
		return errors.Wrap(err, "append "+chainWeaveIPSec)
	}

	return nil
}

func resetChain(ipt *iptables.IPTables, table, chain string) error {
	if err := ipt.ClearChain(table, chain); err != nil {
		return errors.Wrap(err, "ipt.ClearChain")
	}

	if err := ipt.DeleteChain(table, chain); err != nil {
		// TODO(mp) "thisisfine" or fix coreos/go-iptables
		if !strings.Contains(err.Error(), "No chain/target/match by that name") {
			return errors.Wrap(err, "ipt.DeleteChain")
		}
	}

	if err := ipt.NewChain(table, chain); err != nil {
		return errors.Wrap(err, "new chain "+chain)
	}

	return nil
}
