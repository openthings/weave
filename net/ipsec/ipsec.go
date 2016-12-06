package ipsec

// TODO
// * Handle the case when params.RemoteAddr is not present.
// * Remove fastdp flows upon `weave reset`.
// * Remove ipsec upon `weave reset`.
// * Handle EEXIST for XFRM policies / SAs (best-effort?)
// * What happens in the case of fastdp->sleeve, does Stop get called?

// * Tests.
// * Design documentation.
// * Test NAT-T in tunnel mode (fragmentation might be an issue).
// * Check how k8s does marking to prevent possible collisions.
// * Do not store {local,reset}SAKey in mesh connection state.
//
// * Cleanup log messages.
// * Cleanup errors.Wrap.
//
// * type IPSec struct { ipt *iptables.IPTables }
//
// * Various XFRM related improvements to vishvananda/netlink.
// * Patch the kernel.
//
// * Overhead for having additional chain.
// * transport vs tunnel mode benchmarks.

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
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

	skbMark = uint32(0x77766e74)
)

type IPSec struct {
	ipt *iptables.IPTables
	// reference counting for IPSec connections as mesh simultaneously might
	// create two connections at the same time (hence, PrepareConnection is
	// invoked twice for the same peer pair).
	connRefs map[[12]byte]int
}

// API

func New() (*IPSec, error) {
	ipt, err := iptables.New()
	if err != nil {
		return nil, errors.Wrap(err, "iptables new")
	}

	ipsec := &IPSec{
		ipt:      ipt,
		connRefs: make(map[[12]byte]int),
	}

	return ipsec, nil
}

// A Reset flushes relevant XFRM polices / SAs and resets relevant iptables
// rules.
func (ipsec *IPSec) Reset() error {
	spis := make(map[SPI]struct{})

	policies, err := netlink.XfrmPolicyList(syscall.AF_INET)
	if err != nil {
		return errors.Wrap(err, "xfrm policy list")
	}
	for _, p := range policies {
		if p.Mark != nil && p.Mark.Value == skbMark {
			// TODO(mp) this might fail, maybe ignore if tmpls is nil?
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

	if err := ipsec.resetIPTables(); err != nil {
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

	key := connRefsKey(srcIP, dstIP, outSPI)
	ipsec.connRefs[key]++

	if ipsec.connRefs[key] > 1 {
		// IPSec has been already set up
		return outSPI, nil
	}

	inSPI, err := newSPI(dstPeer, srcPeer)
	if err != nil {
		return 0,
			errors.Wrap(err, fmt.Sprintf("derive SPI (%x, %x)", dstPeer, srcPeer))
	}

	// TODO(mp) make sure that keys are not logged

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

	outPolicy := xfrmPolicy(srcIP, dstIP, outSPI)
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

	key := connRefsKey(srcIP, dstIP, outSPI)
	ipsec.connRefs[key]--

	switch {
	case ipsec.connRefs[key] > 0:
		return nil
	case ipsec.connRefs[key] < 0:
		return fmt.Errorf("IPSec invalid state")
	}

	if err = netlink.XfrmPolicyDel(xfrmPolicy(srcIP, dstIP, outSPI)); err != nil {
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

// iptables

func (ipsec *IPSec) installMarkRule(srcIP, dstIP net.IP, dstPort int) error {
	rulespec := []string{
		"-s", srcIP.String(), "-d", dstIP.String(),
		"-p", "udp", "--dport", strconv.FormatUint(uint64(dstPort), 10),
		"-j", markChain,
	}
	if err := ipsec.ipt.AppendUnique(table, mainChain, rulespec...); err != nil {
		return errors.Wrap(err, fmt.Sprintf("iptables append (%s, %s, %s)", table, mainChain, rulespec))
	}

	return nil
}

// TODO(mp) DRY
func (ipsec *IPSec) removeMarkRule(srcIP, dstIP net.IP, dstPort int) error {
	rulespec := []string{
		"-s", srcIP.String(), "-d", dstIP.String(),
		"-p", "udp", "--dport", strconv.FormatUint(uint64(dstPort), 10),
		"-j", markChain,
	}
	if err := ipsec.ipt.Delete(table, mainChain, rulespec...); err != nil {
		return errors.Wrap(err, fmt.Sprintf("iptables delete (%s, %s, %s)", table, mainChain, rulespec))
	}

	return nil
}

func (ipsec *IPSec) resetIPTables() error {
	if err := ipsec.ipt.ClearChain(table, mainChain); err != nil {
		return errors.Wrap(err, fmt.Sprintf("iptables clear (%s, %s)", table, mainChain))
	}

	if err := ipsec.ipt.ClearChain(table, markChain); err != nil {
		return errors.Wrap(err, fmt.Sprintf("iptables clear (%s, %s)", table, markChain))
	}

	if err := ipsec.ipt.AppendUnique(table, "OUTPUT", "-j", mainChain); err != nil {
		return errors.Wrap(err, fmt.Sprintf("iptables append (%s, %s)", table, "OUTPUT"))
	}

	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, skbMark)
	rulespec := []string{"-j", "MARK", "--set-mark", "0x" + hex.EncodeToString(b)}
	if err := ipsec.ipt.Append(table, markChain, rulespec...); err != nil {
		return errors.Wrap(err, fmt.Sprintf("iptables append (%s, %s, %s)", table, markChain, rulespec))
	}

	return nil
}

// helpers

func xfrmState(srcIP, dstIP net.IP, spi SPI, key []byte) (*netlink.XfrmState, error) {
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

func xfrmPolicy(srcIP, dstIP net.IP, spi SPI) *netlink.XfrmPolicy {
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

func reverseSPI(spi SPI) SPI {
	return SPI(uint32(spi)>>16 | uint32(spi)<<16)
}

func connRefsKey(srcIP, dstIP net.IP, spi SPI) (key [12]byte) {
	copy(key[:], srcIP.To4())
	copy(key[4:], dstIP.To4())
	binary.BigEndian.PutUint32(key[8:], uint32(spi))

	return
}
