package rule

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"testing"
	"upf/internal/pkg/port/pcap"
)

func TestTemplate(t *testing.T) {

	eth := &layers.Ethernet{
		SrcMAC:       []byte{1, 2, 3, 4, 5, 6},
		DstMAC:       []byte{7, 8, 8, 8, 8, 8},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipLayer := &layers.IPv4{
		Version:  4,
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

	if err := udpLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
		t.Fatalf("set failed %+v", err)
	}

	a := pduSessionContainer{
		pduType: 0,
		PPP:     true,
		RQI:     false,
		QFI:     2,
		PPI:     0,
	}

	content := a.Marshal()
	x := 0
	if (len(content)+2)%4 > 0 {
		x = (len(content)+2)/4 + 1
	} else {
		x = (len(content) + 2) / 4
	}

	gtpLayer := &layers.GTPv1U{
		Version:             1,
		ProtocolType:        1,
		ExtensionHeaderFlag: true,
		MessageType:         255,
		MessageLength:       uint16((x + 1) * 4),
		TEID:                1234,
		SequenceNumber:      0,
		NPDU:                0,
		GTPExtensionHeaders: []layers.GTPExtensionHeader{
			{
				Type:    0x85,
				Content: a.Marshal(),
			},
		},
	}

	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	ls := []gopacket.SerializableLayer{
		eth,
		ipLayer,
		udpLayer,
		gtpLayer,
	}

	// And create the packet with the layers
	buffer := gopacket.NewSerializeBuffer()

	err := gopacket.SerializeLayers(buffer, options,
		ls...,
	)

	if err != nil {
		t.Fatal(err, "serialize layers failed")
	}

	outgoingPacket := buffer.Bytes()

	pcap.WritePacket("rule.test", outgoingPacket)

	packet := gopacket.NewPacket(outgoingPacket, layers.LayerTypeIPv4, gopacket.Default)

	fmt.Println(packet.Dump())
}
