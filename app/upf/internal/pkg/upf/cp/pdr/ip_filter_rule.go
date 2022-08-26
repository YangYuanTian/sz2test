package pdr

import (
	"encoding/json"
	"fmt"
	"lite5gc/cmn/rlogger"
	"regexp"
	"strconv"
	"strings"
)

//RFC 6733 Diameter Base Protocol             October 2012

/*IPFilterRule filters MUST follow the format:

  action dir proto from src to dst [options]
*/
/*
Direction
Source and destination IP address
Protocol
Source and destination port
TCP flags
IP fragment flag
IP options
ICMP types
*/

/*action       permit - Allow packets that match the rule.
  deny   - Drop packets that match the rule.*/
/*dir          "in" is from the terminal, "out" is to the
  terminal.*/
//proto        An IP protocol specified by number.  The "ip"
//                      keyword means any protocol will match.

// src and dst  <address/mask> [ports]
//
//                      The <address/mask> may be specified as:
//                      ipno       An IPv4 or IPv6 number in dotted-
//                                 quad or canonical IPv6 form.  Only
//                                 this exact IP number will match the
//                                 rule.
/* ipno/bits  An IP number as above with a mask
width of the form 192.0.2.10/24.  In
this case, all IP numbers from
192.0.2.0 to 192.0.2.255 will match.
The bit width MUST be valid for the
IP version, and the IP number MUST
NOT have bits set beyond the mask.
For a match to occur, the same IP
version must be present in the
packet that was used in describing
the IP address.  To test for a
particular IP version, the bits part
can be set to zero.  The keyword
"any" is 0.0.0.0/0 or the IPv6
equivalent.  The keyword "assigned"
is the address or set of addresses
assigned to the terminal.  For IPv4,
a typical first rule is often "deny
in ip! assigned".*/

// eg. action dir proto from src to dst [options]
// "permit out ip from 192.0.2.10/24 5000 to 192.0.2.20/24 6000-8000"

// 使用json 编码实现
//{"action":"permit","dir":"out","proto":"udp","src_ip":"192.0.2.10/24","dst_ip":"192.0.2.20/24","src_port":"5000","dst_port":"6000-8000"}
/*{
"action": "permit",
"dir": "out",              //对应Down link
"proto": "udp",
"src_ip": "192.0.2.10/24", //对应DN IP
"dst_ip": "192.0.2.20/24", //对应UE IP
"src_port": "5000",
"dst_port": "6000-8000"
}*/

type IPFilterRule struct {
	Action          string `json:"action"`
	Direction       string `json:"dir"` //out:对应下行链路
	Protocol        string `json:"proto"`
	SourceIP        string `json:"src_ip"` // 对应DN IP
	DestinationIP   string `json:"dst_ip"` // 对应终端IP
	SourcePort      string `json:"src_port,omitempty"`
	DestinationPort string `json:"dst_port,omitempty"`
	TCPFlags        string `json:"tcp_flags,omitempty"`
	IPFragmentFlag  string `json:"ip_fragment_flag,omitempty"`
	IPOptions       string `json:"ip_options,omitempty"`
	ICMPTypes       string `json:"icmp_types,omitempty"`
}

var defaultIPFilterRule = IPFilterRule{
	Action:    "permit",
	Direction: "out",
	Protocol:  "ip",
}

// Encode
func (r *IPFilterRule) Encode() []byte {
	b, err := json.Marshal(r)
	if err != nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, nil, "IPFilterRule Coding Failure.")
		return nil
	}
	return b
}

// Decode
func (r *IPFilterRule) Decode(src []byte) error {
	if err := json.Unmarshal(src, r); err != nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, nil, "IPFilterRule Decoding Failed.")
		return err
	}
	return nil
}

// 协议标准解码
func (r *IPFilterRule) DecodeStd(src []byte) error {
	//permit out <ip | protocal number> from <any | ipaddr | ipaddr/mask> [port | port range] to <assigned | ipaddr | ipaddr/mask> [port | port range]
	//Flow Description: permit out 17 from any 5000 to assigned 1025-65535
	// Standard format check
	lowerStr := strings.ToLower(string(src))
	validSdf := regexp.MustCompile(`^[ ]*(permit|deny)[ ]+(out|in)[ ]+(.+)[ ]from[ ]+(.+)[ ]to[ ]+(.*)$`)
	if !validSdf.MatchString(lowerStr) {
		rlogger.Trace(moduleTag, rlogger.ERROR, nil, "IPFilterRule Decoding Failed,illegal format", lowerStr)
		*r = defaultIPFilterRule
		return fmt.Errorf("illegal format")
	}

	strList := strings.Fields(lowerStr)

	if len(strList) < 7 {
		rlogger.Trace(moduleTag, rlogger.ERROR, nil, "IPFilterRule Decoding Failed,len(%d)", len(strList))
		*r = defaultIPFilterRule
		return fmt.Errorf("illegal format,len(%d)", len(strList))
	}
	r.Action = strList[0]
	r.Direction = strList[1]
	r.Protocol = strList[2]
	if strList[3] != "from" {
		rlogger.Trace(moduleTag, rlogger.ERROR, nil, "IPFilterRule Decoding Failed to 'from'.")
		*r = defaultIPFilterRule
		return fmt.Errorf("illegal format")
	}
	if strList[4] == "any" {
		r.SourceIP = "0.0.0.0/0"
	} else {
		r.SourceIP = strList[4]
	}

	if strList[5] == "to" {
		if strList[6] == "assigned" {
			r.DestinationIP = "0.0.0.0/0"
		} else {
			r.DestinationIP = strList[6]
		}
		if len(strList) == 8 {
			r.DestinationPort = strList[len(strList)-1]
		}
	} else if strList[6] == "to" {
		r.SourcePort = strList[5]

		if len(strList) >= 8 {
			if strList[7] == "assigned" {
				r.DestinationIP = "0.0.0.0/0"
			} else {
				r.DestinationIP = strList[7]
			}

			if len(strList) == 9 {
				r.DestinationPort = strList[len(strList)-1]
			}
		}
	}

	return nil
}

type IPProtocol uint8

const (
	IPProtocolReserved IPProtocol = 0
	//IPProtocolIPv6HopByHop    IPProtocol = 0
	IPProtocolICMPv4          IPProtocol = 1
	IPProtocolIGMP            IPProtocol = 2
	IPProtocolIPv4            IPProtocol = 4
	IPProtocolTCP             IPProtocol = 6
	IPProtocolUDP             IPProtocol = 17
	IPProtocolRUDP            IPProtocol = 27
	IPProtocolIPv6            IPProtocol = 41
	IPProtocolIPv6Routing     IPProtocol = 43
	IPProtocolIPv6Fragment    IPProtocol = 44
	IPProtocolGRE             IPProtocol = 47
	IPProtocolESP             IPProtocol = 50
	IPProtocolAH              IPProtocol = 51
	IPProtocolICMPv6          IPProtocol = 58
	IPProtocolNoNextHeader    IPProtocol = 59
	IPProtocolIPv6Destination IPProtocol = 60
	IPProtocolOSPF            IPProtocol = 89
	IPProtocolIPIP            IPProtocol = 94
	IPProtocolEtherIP         IPProtocol = 97
	IPProtocolVRRP            IPProtocol = 112
	IPProtocolSCTP            IPProtocol = 132
	IPProtocolUDPLite         IPProtocol = 136
	IPProtocolMPLSInIP        IPProtocol = 137
)

func (i IPProtocol) String() string {
	switch i {
	case IPProtocolICMPv4:
		return "ICMPv4"
	case IPProtocolIGMP:
		return "IGMP"
	case IPProtocolIPv4:
		return "IPv4"
	case IPProtocolTCP:
		return "TCP"
	case IPProtocolUDP:
		return "UDP"
	case IPProtocolRUDP:
		return "RUDP"
	case IPProtocolIPv6:
		return "IPv6"
	case IPProtocolIPv6Routing:
		return "IPv6Routing"
	case IPProtocolIPv6Fragment:
		return "IPv6Fragment"
	case IPProtocolGRE:
		return "GRE"
	case IPProtocolESP:
		return "ESP"
	case IPProtocolAH:
		return "AH"
	case IPProtocolICMPv6:
		return "ICMPv6"
	case IPProtocolNoNextHeader:
		return "NoNextHeader"
	case IPProtocolIPv6Destination:
		return "IPv6Destination"
	case IPProtocolOSPF:
		return "OSPF"
	case IPProtocolIPIP:
		return "IPIP"
	case IPProtocolEtherIP:
		return "EtherIP"
	case IPProtocolVRRP:
		return "VRRP"
	case IPProtocolSCTP:
		return "SCTP"
	case IPProtocolUDPLite:
		return "UDPLite"
	case IPProtocolMPLSInIP:
		return "MPLSInIP"
	case IPProtocolReserved:
		return "ip"
	}
	return ""
}

// port : 6000-8000
func ParsePortRange(portStr string) PortRange {
	//net.SplitHostPort()
	portRange := PortRange{}

	portStr = strings.TrimSpace(portStr)
	portSet := strings.Split(portStr, "-")

	if len(portSet) == 1 {
		portRange.MinPort, _ = strconv.Atoi(portSet[0])
		portRange.MaxPort = portRange.MinPort
	}
	if len(portSet) == 2 {
		portRange.MinPort, _ = strconv.Atoi(portSet[0])
		portRange.MaxPort, _ = strconv.Atoi(portSet[1])
		if portRange.MinPort > portRange.MaxPort {
			portRange.MinPort, portRange.MaxPort = portRange.MaxPort, portRange.MinPort
		}
	}
	return portRange
}

// ip to ip/mask
// 10.180.1.123 to 10.180.1.123/32
func IpToIpMask(srcIp string) string {
	i := strings.IndexByte(srcIp, '/')
	if i < 0 {
		srcIp = srcIp + "/32"
	}
	return srcIp
}
