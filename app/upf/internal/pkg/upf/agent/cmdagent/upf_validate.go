package oamagent

type UpfHint struct {
	Error   string
	Hint    string
	Example string
}

func UpfSeidHint() UpfHint {
	seid := UpfHint{
		"Missing SEID parameter after SMFSESSIONSEID",
		"Please bring a seid of type int64",
		"cli show upf upfsessionseid 123",
	}
	return seid
}
func UpfIpHint() UpfHint {
	ip := UpfHint{
		"IP address missing after UPFSESSIONIP",
		"Please bring the IP address",
		"cli show upf upfsessionip 0.0.0.1",
	}
	return ip
}
func UpfTiedHint() UpfHint {
	tied := UpfHint{
		"Upfsessiontied is missing the tied parameter",
		"Please bring a parameter of type uint32",
		"cli show upf upfsessiontied 123",
	}
	return tied
}

func UpfValidateParams() UpfHint {
	Validate := UpfHint{
		"There are no parameters to look for",
		"The searched parameter does not exist",
		"cli show [command] help",
	}
	return Validate
}
func PfcfUpfParam() UpfHint {
	pfcf := UpfHint{
		"please bring parameters",
		"please bring business name and switch",
		"cli show upf pfcp ddnd:on",
	}
	return pfcf
}

type UpfPfcp struct {
	Error string
	Hint  string
}

func UpfPfcpValidate() UpfPfcp {
	Def := UpfPfcp{
		"input feature param error",
		"cli show smf help",
	}
	return Def
}

func UpfPfcpSwitch() UpfPfcp {
	Def := UpfPfcp{
		"input switch param error",
		"cli show smf help",
	}
	return Def
}

type UpfH struct {
	Usage          string
	Example        string
	Conf           string
	N3             string
	N4             string
	N6             string
	Nff            string
	Dnn_info       string
	N3_gateway     string
	Pm             string
	Version        string
	Logger         string
	PacketCapture  string
	Upfsessionseid string
	Upfsessionip   string
	Upfsessiontied string
	Upfarptable    string
	Upfcontextn3   string
	Upfcontextn6   string
	Pfcp           string
	PFcp           string
	Timer          string
	PfcpHelp       string
	Hugapage       string
	Nic            string
	Upfsbi         string
	Upfselection   string
	Dpdktools      string
	UseKni         string
	UpfN3N6Capture string
	UpfCapture     string
	Offline        string
	Suspended      string
}

func UpfHelp() UpfH {
	upf := UpfH{
		"          cli show upf [args] //With the following parameters",
		"        cli show upf conf",
		"           cli show upf  conf  ",
		"             cli show upf n3 ",
		"             cli show upf n4 ",
		"             cli show upf n6 ",
		"            cli show upf nff ",
		"       cli show upf dnn_info ",
		"     cli show upf n3_gateway ",
		"             cli show upf pm ",
		"        cli show upf version ",
		"         cli show upf logger",
		"  cli show upf packetcapture ",
		"   cli show upf ueip  IPAddress//Query session information based on ue ip,eg:cli show upf ueip 10.55.6.2",
		"    cli show upf upfarptable  ",
		"   cli show upf upfcontextn3 ",
		"   cli show upf upfcontextn6",
		"          cli show upf timer",
		"       cli show upf pfcphelp",
		"       cli show upf hugepage",
		"            cli show upf nic",
		"         cli show  upf upfsbi ",
		"   cli show upf upfselection",
		"   cli show upf tools (showport|pportstat:on/off|PortIfUp:0_up/0_down|EthPromiscuous:0_on/0_off|meminfodisplay|PrintRingsCount|showring|showmempool|ReportMempoolsState|showtm)",
		" cli show upf tools usekni:on",
		" cli show upf tools n3n6capstart:on",
		" cli show upf tools capstart:on  //on(start capture) off(close capture) show (display cap info) clean(remove files) cleanall(remove all files including history files)",
		"cli show upf pfcp offline:on // only use (on) ,not use (off). notify all SMF , the UPF become offline status , release nodes information.",
		"cli show upf pfcp suspended:on // only use (on) ,not use (off). Let the UPF program exit abnormally,can test the stateless restart of UPF.",
		"",
		"",
		"",
		"",
	}
	return upf
}

type PfcpHelp struct {
	Bucp      string
	Ddnd      string
	Dlbd      string
	Trst      string
	Ftup      string
	Pfdm      string
	Heeu      string
	Treu      string
	Empu      string
	Pdiu      string
	Udbc      string
	Quoac     string
	Trace     string
	Frrt      string
	Offline   string
	Suspended string
}

func HintUpfPfcp() PfcpHelp {
	pf := PfcpHelp{
		"Downlink Data Buffering in CP function is supported by the UP function",
		"The buffering parameter 'Downlink Data Notification Delay' is supported by the UP function ",
		"The buffering parameter 'DL Buffering Duration' is supported by the UP function ",
		"Traffic Steering is supported by the UP function",
		"F-TEID allocation / release in the UP function is supported by the UP function ",
		"The PFD Management procedure is supported by the UP function ",
		"Header Enrichment of Uplink traffic is supported by the UP function ",
		"Traffic Redirection Enforcement in the UP function is supported by the UP function ",
		"Sending of End Marker packets supported by the UP function ",
		"Support of PDI optimised signalling in UP function ",
		"Support of UL/DL Buffering Control",
		"The UP function supports being provisioned with the Quota Action to apply when reaching quotas",
		"The UP function supports Trace (see subclause 5.x) ",
		"The UP function supports Framed Routing ",
		"The UP function Supports UPF notify all SMF Own offline(cli show upf pfcp offline:on) ",
		"(cli show upf pfcp suspended:on) Let the UPF program exit abnormally,can test the stateless restart of UPF.",
	}
	return pf
}
