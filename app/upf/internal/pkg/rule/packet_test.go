package rule

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"testing"
)

func TestTemplate(t *testing.T) {

	ipLayer := &layers.IPv4{
		Protocol: layers.IPProtocolUDP,
		IHL:      0x45,
		TTL:      0x80,
		Id:       0x1234,
		SrcIP:    []byte{1, 1, 1, 1},
		DstIP:    []byte{2, 3, 4, 5},
	}

	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(2152),
		DstPort: layers.UDPPort(2152),
	}

	gtpLayer := &layers.GTPv1U{
		Version:             1,
		ProtocolType:        1,
		ExtensionHeaderFlag: false,
		MessageType:         255,
		TEID:                1234,
	}

	options := gopacket.SerializeOptions{
		FixLengths:       false,
		ComputeChecksums: false,
	}

	// And create the packet with the layers
	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options,
		ipLayer,
		udpLayer,
		gtpLayer,
	)

	if err != nil {
		t.Fatal(err, "serialize layers failed")
	}

	outgoingPacket := buffer.Bytes()

	if len(outgoingPacket) > 48 {
		t.Fatal("packet length is too long")
	}

	packet := gopacket.NewPacket(outgoingPacket, layers.LayerTypeIPv4, gopacket.Default)

	t.Log(packet.Dump())
}
