package n4layer

import (
	"github.com/davecgh/go-spew/spew"
	"github.com/pkg/errors"
	"lite5gc/cmn/message/pfcp"
	"lite5gc/cmn/types3gpp"
	"net"
)

type TestUser struct {
	UEIP    string
	GNBIP   string
	GNBTEID uint32
	N3IP    string
	N3TEID  uint32
	Enable  bool
}

func (t *TestUser) Completed() *TestUser {

	if t.UEIP == "" {
		t.UEIP = "10.55.6.2"
	}

	if t.GNBIP == "" {
		t.GNBIP = "172.17.0.2"
	}

	if t.GNBTEID == 0 {
		t.GNBTEID = 0x00000001
	}

	if t.N3IP == "" {
		t.N3IP = "172.17.0.210"
	}

	if t.N3TEID == 0 {
		t.N3TEID = 0x001e8480
	}

	return t
}

func (t *TestUser) Create() error {

	if !t.Enable {
		return nil
	}

	establishReq := t.Completed().defaultSessionEstablishReq()

	msg := new(N4Msg)
	res := new(pfcp.SessionEstablishmentResponse)

	err := msg.SessionEstablishmentRequest(*establishReq, res)
	if err != nil {
		return errors.WithStack(err)
	}

	modify := t.defaultSessionModifyReq()

	modifyRes := new(pfcp.SessionModifyResponse)

	return msg.SessionModifyRequest(*modify, modifyRes)
}

func (t *TestUser) Delete() error {

	msg := new(N4Msg)
	req := t.defaultSessionDelete()
	res := new(pfcp.SessionReleaseResponse)

	return msg.SessionReleaseRequest(*req, res)
}

func (t *TestUser) Show() string {
	return spew.Sdump(t)
}

func (t *TestUser) defaultSessionEstablishReq() *pfcp.SessionEstablishmentRequest {

	req := pfcp.SessionEstablishmentRequest{}

	req.PfcpHeader = pfcp.PfcpHeaderforSession{
		MessageType:    pfcp.PFCP_Session_Establishment_Request,
		SequenceNumber: 2,
	}

	req.IE = pfcp.IEsSessionEstablishmentRequest{
		NodeID: pfcp.IENodeID{
			NodeIDType:  0,
			NodeIDvalue: net.ParseIP("172.17.0.213"),
		},
		CPFSEID: pfcp.IEFSEID{
			V4Flag:   1,
			SEID:     0x0000000000002711,
			IPv4Addr: net.ParseIP("172.17.0.213"),
		},
		CreatePDRs: []*pfcp.IECreatePDR{
			{
				PDRID: pfcp.IEPDRID{
					RuleID: 1,
				},
				Precedence: pfcp.IEPrecedence{
					PrecedenceValue: 255,
				},
				PDI: pfcp.IEPDI{
					SourceInterface: pfcp.IESourceInterface{
						InterfaceValue: 0, // Source Interface: Access (0)
					},
					LocalFTEID: &pfcp.IEFTEID{
						V4Flag:   1,
						TEID:     types3gpp.Teid(t.N3TEID),
						IPv4Addr: net.ParseIP(t.N3IP),
					},
					UEIPaddress: &pfcp.IEUEIPaddress{
						V4Flag:   1,
						IPv4Addr: net.ParseIP(t.UEIP),
					},
					SDFFilters: []*pfcp.IESDFFilter{
						{
							BIDFlag:                 true,
							FDFlag:                  true,
							LengthofFlowDescription: 34,
							FlowDescription:         []byte("permit out ip from any to assigned"),
							SDFFilterID:             1,
						},
					},
					QFIs: []*pfcp.IEQFI{
						{
							Value: 1,
						},
					},
				},
				OuterHeaderRemoval: &pfcp.IEOuterHeaderRemoval{
					Description: 0, //Outer Header Removal Description: GTP-U/UDP/IPv4 (0)
				},
				FARID: &pfcp.IEFARID{
					Value: 1,
				},
				QERIDs: []*pfcp.IEQERID{
					{
						Value: 1,
					},
				},
			},
			{
				PDRID: pfcp.IEPDRID{
					RuleID: 2,
				},
				Precedence: pfcp.IEPrecedence{
					PrecedenceValue: 255,
				},
				PDI: pfcp.IEPDI{
					SourceInterface: pfcp.IESourceInterface{
						InterfaceValue: 1, //Source Interface: Core (1)
					},
					UEIPaddress: &pfcp.IEUEIPaddress{
						SD:       1,
						V4Flag:   1,
						IPv4Addr: net.ParseIP(t.UEIP),
					},
					SDFFilters: []*pfcp.IESDFFilter{
						{
							BIDFlag:     true,
							SDFFilterID: 1,
						},
					},
				},
				FARID: &pfcp.IEFARID{
					Value: 2,
				},
				QERIDs: []*pfcp.IEQERID{
					{
						Value: 1,
					},
				},
			},
		},
		CreateFARs: []*pfcp.IECreateFAR{
			{
				FARID: pfcp.IEFARID{
					Value: 1,
				},
				ApplyAction: pfcp.IEApplyAction{
					Flag: 0x2, //Apply Action: Forwarding (2)
				},
				ForwardingParameters: &pfcp.IEForwardingParameters{
					DstInterface: pfcp.IEDestinationInterface{
						Value: 1, // Destination Interface: core (1)
					},
				},
			},
			{
				FARID: pfcp.IEFARID{
					Value: 2,
				},
				ApplyAction: pfcp.IEApplyAction{
					Flag: 0x0c, //NOCP BUFF
				},
				BARID: &pfcp.IEBARID{Value: 1}, // BAR ID: 1
			},
		},
		CreateQERs: []*pfcp.IECreateQER{
			{
				QERID: pfcp.IEQERID{
					Value: 1,
				},
				GateStatus: pfcp.IEGateStatus{
					ULGate: 0,
					DLGate: 0,
				},
				MaximumBitrate: pfcp.IEMBR{
					ULMBR: 1,
					DLMBR: 1,
				},
				QoSflowidentifier: pfcp.IEQFI{
					Value: 1,
				},
			},
		},
		CreateBAR: &pfcp.IECreateBAR{
			BARID: pfcp.IEBARID{
				Value: 1,
			},
		},
		PDNType: &pfcp.IEPDNType{
			PDNType: 1,
		},
	}

	return &req
}

func (t *TestUser) defaultSessionModifyReq() *pfcp.SessionModifyRequest {
	req := pfcp.SessionModifyRequest{}

	req.PfcpHeader = pfcp.PfcpHeaderforSession{
		MessageType:    pfcp.PFCP_Session_Modification_Request,
		SEID:           0,
		SequenceNumber: 4,
	}

	req.IE = pfcp.IEsSessionModifyRequest{
		UpdateFARs: []*pfcp.IEUpdateFAR{
			{
				FARID: pfcp.IEFARID{
					Value: 2,
				},
				ApplyAction: pfcp.IEApplyAction{
					Flag: 2,
				},
				UpdateForwardingPara: &pfcp.IEUpdateForwardingParameters{
					DstInterface: &pfcp.IEDestinationInterface{
						Value: 0,
					},
					OuterHeaderCreation: &pfcp.IEOuterHeaderCreation{
						Description: 256, //Outer Header Creation Description: GTP-U/UDP/IPv4  (256)
						TEID:        types3gpp.Teid(t.GNBTEID),
						IPv4Addr:    net.ParseIP(t.GNBIP),
					},
				},
			},
		},
	}
	return &req
}

func (t *TestUser) defaultSessionDelete() *pfcp.SessionReleaseRequest {
	req := pfcp.SessionReleaseRequest{}

	req.PfcpHeader = pfcp.PfcpHeaderforSession{
		MessageType:    pfcp.PFCP_Session_Deletion_Request,
		SEID:           0,
		SequenceNumber: 4,
	}

	return &req
}
