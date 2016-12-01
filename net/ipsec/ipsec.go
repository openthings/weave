package ipsec

import (
	"fmt"
	"net"
	"syscall"

	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"

	"github.com/weaveworks/mesh"
)

type SPI uint32

// API

func Reset() error {
	// TODO(mp) Select relevant fields

	if err := netlink.XfrmPolicyFlush(); err != nil {
		return errors.Wrap(err, "xfrm policy flush")
	}

	if err := netlink.XfrmStateFlush(netlink.XFRM_PROTO_ESP); err != nil {
		return errors.Wrap(err, "xfrm state flush")
	}

	return nil
}

func Setup(srcPeer, dstPeer mesh.PeerShortID, srcIP, dstIP net.IP, sessionKey []byte) error {
	outSPI, err := newSPI(srcPeer, dstPeer)
	if err != nil {
		return errors.Wrap(err, "new SPI")
	}
	inSPI, err := newSPI(dstPeer, srcPeer)
	if err != nil {
		return errors.Wrap(err, "new SPI")
	}

	inSA := newXfrmState(dstIP, srcIP, inSPI, sessionKey)
	if err := netlink.XfrmStateAdd(inSA); err != nil {
		// TODO(mp) make sure that sessionKey is not logged
		return errors.Wrap(err, "xfrm state (in) add")
	}
	// TODO(mp) use a sessionKey per direction
	outSA := newXfrmState(srcIP, dstIP, outSPI, sessionKey)
	if err := netlink.XfrmStateAdd(outSA); err != nil {
		return errors.Wrap(err, "xfrm state (out) add")
	}

	outPolicy := newXfrmPolicy(srcIP, dstIP, outSPI)
	if err := netlink.XfrmPolicyAdd(outPolicy); err != nil {
		return errors.Wrap(err, "xfrm policy add")
	}

	return nil
}

func Teardown() {}

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

func newXfrmState(srcIP, dstIP net.IP, spi SPI, key []byte) *netlink.XfrmState {
	return &netlink.XfrmState{
		Src:   srcIP,
		Dst:   dstIP,
		Proto: netlink.XFRM_PROTO_ESP, // TODO(mp) s/Proto/XfrmProto
		Mode:  netlink.XFRM_MODE_TRANSPORT,
		Spi:   int(spi), // TODO(mp) s/int/uint32
		Aead: &netlink.XfrmStateAlgo{
			Name:   "rfc4106(gcm(aes))",
			Key:    key[:20], // TODO(mp) generate 36 octets
			ICVLen: 128,
		},
	}
}

func newXfrmPolicy(srcIP, dstIP net.IP, spi SPI) *netlink.XfrmPolicy {
	ipMask := []byte{0xff, 0xff, 0xff, 0xff} // /32
	return &netlink.XfrmPolicy{
		Src:   &net.IPNet{srcIP, ipMask},
		Dst:   &net.IPNet{dstIP, ipMask},
		Proto: syscall.IPPROTO_UDP,
		Dir:   netlink.XFRM_DIR_OUT,
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
