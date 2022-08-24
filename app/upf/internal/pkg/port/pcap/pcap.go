package pcap

import (
	"fmt"
	"os"
)

func isDirExist(dir string) bool {
	if _, err := os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// WritePacket will generate a pcap file for a single packet,
// so you can view this packet in wireshark.
func WritePacket(name string, b []byte) {
	g := &PcapGlobalHear{}
	p := &PacketHeader{}
	dir := "./pcap/"
	if !isDirExist(dir) {
		if err := os.Mkdir(dir, 0777); err != nil {
			fmt.Println(err)
			return
		}
	}
	WriteFile(
		dir+name+".pcap",
		append(g.SetDefault().Marshal(), p.Packing(b)...),
	)
}
func WriteFile(name string, data []byte) error {
	file, err := os.Create(name)
	if err != nil {
		return nil
	}
	file.Write(data)
	file.Close()
	return nil
}

// Pcap will write packets to a pcap file,
// you can call WritePcap repeatedly to store packets.
type Pcap struct {
	FileName string
	File     *os.File
}

func NewPcap(name string) (*Pcap, error) {
	g := &PcapGlobalHear{}
	dir := "./pcap/"
	if !isDirExist(dir) {
		if err := os.Mkdir(dir, 0777); err != nil {
			return nil, err
		}
	}
	file, err := os.Create(dir + name + ".pcap")
	if err != nil {
		return nil, err
	}
	_, err = file.Write(g.SetDefault().Marshal())
	if err != nil {
		return nil, err
	}
	return &Pcap{
		FileName: name,
		File:     file,
	}, nil
}

func (p *Pcap) WritePcap(data []byte) error {
	_, err := p.File.Write(new(PacketHeader).Packing(data))
	if err != nil {
		return err
	}
	return nil
}

func (p *Pcap) Close() error {
	return p.File.Close()
}
