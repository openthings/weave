package ipsec

// TODO
// * Test NAT-T in tunnel mode.
// * Design documentation.
// * Blogpost.
// * Document MTU requirements.
//
// * Extend the heartbeats to check whether encryption is properly set.
// * Rotate keys.

// * Various XFRM related improvements to vishvananda/netlink.
// * Patch the kernel.
//
// * Overhead for having additional chain.
// * Transport vs tunnel mode benchmarks.

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"sync"
	"syscall"

	"github.com/coreos/go-iptables/iptables"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"

	"github.com/weaveworks/mesh"
)

type SPI uint32

const (
	table     = "mangle"
	markChain = "WEAVE-IPSEC-MARK"
	mainChain = "WEAVE-IPSEC"

	// TODO(mp) pass as arg and document it properly
	skbMark    = uint32(0x1) << 17
	skbMarkStr = "0x20000/0x20000"
)

// IPSec

type IPSec struct {
	ipt *iptables.IPTables
	rc  *connRefCount
}

func New() (*IPSec, error) {
	ipt, err := iptables.New()
	if err != nil {
		return nil, errors.Wrap(err, "iptables new")
	}

	ipsec := &IPSec{
		ipt: ipt,
		rc:  newConnRefCount(),
	}

	return ipsec, nil
}

// A Reset flushes relevant XFRM polices / SAs and resets relevant iptables
// rules.
func (ipsec *IPSec) Reset(teardown bool) error {
	spis := make(map[SPI]struct{})

	policies, err := netlink.XfrmPolicyList(syscall.AF_INET)
	if err != nil {
		return errors.Wrap(err, "xfrm policy list")
	}
	for _, p := range policies {
		if p.Mark != nil && p.Mark.Value == skbMark && len(p.Tmpls) != 0 {
			spi := SPI(p.Tmpls[0].Spi)
			spis[spi] = struct{}{}
			spis[reverseSPI(spi)] = struct{}{}

			if err := netlink.XfrmPolicyDel(&p); err != nil {
				return errors.Wrap(err, fmt.Sprintf("xfrm policy del (%s, %s, 0x%x)", p.Src, p.Dst, spi))
			}
		}
	}

	states, err := netlink.XfrmStateList(syscall.AF_INET)
	if err != nil {
		return errors.Wrap(err, "xfrm state list")
	}
	for _, s := range states {
		if _, ok := spis[SPI(s.Spi)]; ok {
			if err := netlink.XfrmStateDel(&s); err != nil {
				return errors.Wrap(err, fmt.Sprintf("xfrm state list (%s, %s, 0x%x)", s.Src, s.Dst, s.Spi))
			}
		}
	}

	if err := ipsec.resetIPTables(teardown); err != nil {
		return errors.Wrap(err, "reset ip tables")
	}

	return nil
}

// A Setup sets up IPSec for a tunnel between srcIP and dstIP.
func (ipsec *IPSec) Setup(srcPeer, dstPeer mesh.PeerShortID, srcIP, dstIP net.IP, dstPort int, localKey, remoteKey []byte) (SPI, error) {
	outSPI, err := newSPI(srcPeer, dstPeer)
	if err != nil {
		return 0,
			errors.Wrap(err, fmt.Sprintf("derive SPI (%x, %x)", srcPeer, dstPeer))
	}

	if ipsec.rc.get(srcIP, dstIP, outSPI) > 1 {
		// IPSec has been already set up between the given peers
		return outSPI, nil
	}

	inSPI, err := newSPI(dstPeer, srcPeer)
	if err != nil {
		return 0,
			errors.Wrap(err, fmt.Sprintf("derive SPI (%x, %x)", dstPeer, srcPeer))
	}

	if inSA, err := xfrmState(dstIP, srcIP, inSPI, remoteKey); err == nil {
		if err := netlink.XfrmStateAdd(inSA); err != nil {
			return 0,
				errors.Wrap(err, fmt.Sprintf("xfrm state add (in, %s, %s, 0x%x)", inSA.Src, inSA.Dst, inSA.Spi))
		}
	} else {
		return 0, errors.Wrap(err, "new xfrm state (in)")
	}

	if outSA, err := xfrmState(srcIP, dstIP, outSPI, localKey); err == nil {
		if err := netlink.XfrmStateAdd(outSA); err != nil {
			return 0,
				errors.Wrap(err, fmt.Sprintf("xfrm state add (out, %s, %s, 0x%x)", outSA.Src, outSA.Dst, outSA.Spi))
		}
	} else {
		return 0, errors.Wrap(err, "new xfrm state (out)")
	}

	outPolicy := xfrmPolicy(srcIP, dstIP, dstPort, outSPI)
	if err := netlink.XfrmPolicyAdd(outPolicy); err != nil {
		return 0,
			errors.Wrap(err, fmt.Sprintf("xfrm policy add (%s, %s, 0x%x)", srcIP, dstIP, outSPI))
	}

	if err := ipsec.installMarkRule(srcIP, dstIP, dstPort); err != nil {
		return 0,
			errors.Wrap(err, fmt.Sprintf("install mark rule (%s, %s, 0x%x)", srcIP, dstIP, dstPort))
	}

	return outSPI, nil
}

func (ipsec *IPSec) Teardown(srcIP, dstIP net.IP, dstPort int, outSPI SPI) error {
	var err error

	count := ipsec.rc.put(srcIP, dstIP, outSPI)
	switch {
	case count > 0:
		return nil
	case count < 0:
		return fmt.Errorf("IPSec invalid state")
	}

	if err = netlink.XfrmPolicyDel(xfrmPolicy(srcIP, dstIP, dstPort, outSPI)); err != nil {
		return errors.Wrap(err,
			fmt.Sprintf("xfrm policy del (%s, %s, 0x%x)", srcIP, dstIP, outSPI))
	}

	inSA := &netlink.XfrmState{
		Src:   srcIP,
		Dst:   dstIP,
		Proto: netlink.XFRM_PROTO_ESP,
		Spi:   int(outSPI),
	}
	outSA := &netlink.XfrmState{
		Src:   dstIP,
		Dst:   srcIP,
		Proto: netlink.XFRM_PROTO_ESP,
		Spi:   int(reverseSPI(outSPI)),
	}
	if err = netlink.XfrmStateDel(inSA); err != nil {
		return errors.Wrap(err,
			fmt.Sprintf("xfrm state del (in, %s, %s, 0x%x)", inSA.Src, inSA.Dst, inSA.Spi))
	}
	if err = netlink.XfrmStateDel(outSA); err != nil {
		return errors.Wrap(err,
			fmt.Sprintf("xfrm state del (out, %s, %s, 0x%x)", outSA.Src, outSA.Dst, outSA.Spi))
	}

	if err = ipsec.removeMarkRule(srcIP, dstIP, dstPort); err != nil {
		return errors.Wrap(err,
			fmt.Sprintf("remove mark rule (%s, %s, %d)", srcIP, dstIP, dstPort))
	}

	return nil
}

// connRefCount

// Reference counting for IPSec connections.
// The motivation for counting is that mesh might simultaneously create two
// connections for the same peer pair. Thus, we need to avoid setting up IPSec
// twice.
type connRefCount struct {
	sync.RWMutex
	ref map[[12]byte]int
}

func newConnRefCount() *connRefCount {
	return &connRefCount{ref: make(map[[12]byte]int)}
}

func (rc *connRefCount) get(srcIP, dstIP net.IP, spi SPI) int {
	rc.Lock()
	defer rc.Unlock()

	key := connRefKey(srcIP, dstIP, spi)
	rc.ref[key]++

	return rc.ref[key]
}

func (rc *connRefCount) put(srcIP, dstIP net.IP, spi SPI) int {
	rc.Lock()
	defer rc.Unlock()

	key := connRefKey(srcIP, dstIP, spi)
	rc.ref[key]--

	return rc.ref[key]
}

// iptables

func (ipsec *IPSec) installMarkRule(srcIP, dstIP net.IP, dstPort int) error {
	rulespec := markRulespec(srcIP, dstIP, dstPort)
	if err := ipsec.ipt.AppendUnique(table, mainChain, rulespec...); err != nil {
		return errors.Wrap(err, fmt.Sprintf("iptables append (%s, %s, %s)", table, mainChain, rulespec))
	}

	return nil
}

func (ipsec *IPSec) removeMarkRule(srcIP, dstIP net.IP, dstPort int) error {
	rulespec := markRulespec(srcIP, dstIP, dstPort)
	if err := ipsec.ipt.Delete(table, mainChain, rulespec...); err != nil {
		return errors.Wrap(err, fmt.Sprintf("iptables delete (%s, %s, %s)", table, mainChain, rulespec))
	}

	return nil
}

func markRulespec(srcIP, dstIP net.IP, dstPort int) []string {
	return []string{
		"-s", srcIP.String(), "-d", dstIP.String(),
		"-p", "udp", "--dport", strconv.FormatUint(uint64(dstPort), 10),
		"-j", markChain,
	}

}

func (ipsec *IPSec) resetIPTables(teardown bool) error {
	if err := ipsec.ipt.ClearChain(table, mainChain); err != nil {
		return errors.Wrap(err, fmt.Sprintf("iptables clear (%s, %s)", table, mainChain))
	}

	if err := ipsec.ipt.ClearChain(table, markChain); err != nil {
		return errors.Wrap(err, fmt.Sprintf("iptables clear (%s, %s)", table, markChain))
	}

	if err := ipsec.ipt.AppendUnique(table, "OUTPUT", "-j", mainChain); err != nil {
		return errors.Wrap(err, fmt.Sprintf("iptables append (%s, %s)", table, "OUTPUT"))
	}

	if !teardown {
		rulespec := []string{"-j", "MARK", "--set-xmark", skbMarkStr}
		if err := ipsec.ipt.Append(table, markChain, rulespec...); err != nil {
			return errors.Wrap(err, fmt.Sprintf("iptables append (%s, %s, %s)", table, markChain, rulespec))
		}

		return nil
	}

	if err := ipsec.ipt.Delete(table, "OUTPUT", "-j", mainChain); err != nil {
		return errors.Wrap(err, fmt.Sprintf("iptables delete (%s, %s)", table, "OUTPUT"))
	}

	if err := ipsec.ipt.DeleteChain(table, mainChain); err != nil {
		return errors.Wrap(err, fmt.Sprintf("iptables delete (%s, %s)", table, mainChain))
	}

	if err := ipsec.ipt.DeleteChain(table, markChain); err != nil {
		return errors.Wrap(err, fmt.Sprintf("iptables delete (%s, %s)", table, mainChain))
	}

	return nil
}

// xfrm

func xfrmState(srcIP, dstIP net.IP, spi SPI, key []byte) (*netlink.XfrmState, error) {
	if len(key) != 36 {
		return nil, fmt.Errorf("key should be 36 bytes long")
	}

	return &netlink.XfrmState{
		Src:   srcIP,
		Dst:   dstIP,
		Proto: netlink.XFRM_PROTO_ESP,
		Mode:  netlink.XFRM_MODE_TRANSPORT,
		Spi:   int(spi),
		Aead: &netlink.XfrmStateAlgo{
			Name:   "rfc4106(gcm(aes))",
			Key:    key,
			ICVLen: 128,
		},
	}, nil
}

func xfrmPolicy(srcIP, dstIP net.IP, dstPort int, spi SPI) *netlink.XfrmPolicy {
	ipMask := []byte{0xff, 0xff, 0xff, 0xff} // /32

	return &netlink.XfrmPolicy{
		Src:     &net.IPNet{IP: srcIP, Mask: ipMask},
		Dst:     &net.IPNet{IP: dstIP, Mask: ipMask},
		DstPort: dstPort,
		Proto:   syscall.IPPROTO_UDP,
		Dir:     netlink.XFRM_DIR_OUT,
		Mark: &netlink.XfrmMark{
			Value: skbMark,
			Mask:  skbMark,
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

// Helpers

func newSPI(srcPeer, dstPeer mesh.PeerShortID) (SPI, error) {
	if mesh.PeerShortIDBits > 16 { // should not happen
		return 0, fmt.Errorf("PeerShortID too long")
	}

	return SPI(uint32(srcPeer)<<16 | uint32(dstPeer)), nil
}

func reverseSPI(spi SPI) SPI {
	return SPI(uint32(spi)>>16 | uint32(spi)<<16)
}

func connRefKey(srcIP, dstIP net.IP, spi SPI) (key [12]byte) {
	copy(key[:], srcIP.To4())
	copy(key[4:], dstIP.To4())
	binary.BigEndian.PutUint32(key[8:], uint32(spi))

	return
}
