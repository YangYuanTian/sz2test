package utils

import (
	"encoding/binary"
	"errors"
)

// ICMPv4 is the layer for IPv4 ICMP packet data.
type ICMPv4 struct {
	BaseLayer
	TypeCode ICMPv4TypeCode
	Checksum uint16
	Id       uint16
	Seq      uint16
}

type ICMPv4TypeCode uint16

func CreateICMPv4TypeCode(typ uint8, code uint8) ICMPv4TypeCode {
	return ICMPv4TypeCode(binary.BigEndian.Uint16([]byte{typ, code}))
}

// DecodeFromBytes decodes the given bytes into this layer.
func (i *ICMPv4) DecodeFromBytes(data []byte) error {
	if len(data) < 8 {
		return errors.New("ICMP layer less then 8 bytes for ICMPv4 packet")
	}
	i.TypeCode = CreateICMPv4TypeCode(data[0], data[1])
	i.Checksum = binary.BigEndian.Uint16(data[2:4])
	i.Id = binary.BigEndian.Uint16(data[4:6])
	i.Seq = binary.BigEndian.Uint16(data[6:8])
	i.BaseLayer = BaseLayer{data[:8], data[8:]}
	return nil
}

// Partial
func (i *ICMPv4) PartialDecodeFromBytes(data []byte) error {
	if len(data) < 8 {
		return errors.New("ICMP layer less then 8 bytes for ICMPv4 packet")
	}
	//i.TypeCode = CreateICMPv4TypeCode(data[0], data[1])
	return nil
}
