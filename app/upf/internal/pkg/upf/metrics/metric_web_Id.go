package metrics

import (
	"math/rand"
	"upf/internal/pkg/oam/agent/webTypes"
	"upf/internal/pkg/oam/pm"
)

const (
	numTotalPackets          int = 4040010
	numTotalBits             int = 4040011
	numTotalPacketsSec       int = 4040012
	numTotalBitsSec          int = 4040013
	numTotalDiscardedPackets int = 4040014

	numUpLinkTotalPacketsSent              int = 4040015
	numUpLinkPacketsSentSec                int = 4040016
	numUpLinkTotalPacketsReceived          int = 4040017
	numUpLinkPacketsReceivedSec            int = 4040018
	numUpLinkTotalBitsSent                 int = 4040019
	numUpLinkBitsSentSec                   int = 4040020
	numUpLinkTotalBitsReceived             int = 4040021
	numUpLinkBitsReceivedSec               int = 4040022
	numUpLinkTotalReceivedPacketsDiscarded int = 4040023
	numUpLinkTotalSentPacketsDiscarded     int = 4040024
	numUpLinkTotalInvalidPackets           int = 4040025
	numUpLinkTotalDiscardedPackets         int = 4040026

	numDownLinkTotalPacketsSent              int = 4040027
	numDownLinkPacketsSentSec                int = 4040028
	numDownLinkTotalPacketsReceived          int = 4040029
	numDownLinkPacketsReceivedSec            int = 4040030
	numDownLinkTotalBitsSent                 int = 4040031
	numDownLinkBitsSentSec                   int = 4040032
	numDownLinkTotalBitsReceived             int = 4040033
	numDownLinkBitsReceivedSec               int = 4040034
	numDownLinkTotalReceivedPacketsDiscarded int = 4040035
	numDownLinkTotalSentPacketsDiscarded     int = 4040036
	numDownLinkTotalInvalidPackets           int = 4040037
	numDownLinkTotalDiscardedPackets         int = 4040038
	//pfcp
	numPfcpAssociationSetupRequestTotalReceivedPerSec     int = 4040039
	numPfcpAssociationSetupResponseTotalSentPerSec        int = 4040040
	numHeartBeatRequestTotalReceivedPerSec                int = 4040041
	numHeartBeatRequestTotalSentPerSec                    int = 4040042
	numHeartBeatResponseTotalReceivedPerSec               int = 4040043
	numHeartBeatResponseTotalSentPerSec                   int = 4040044
	numPfcpAssociationUpdateRequestTotalReceivedPerSec    int = 4040045
	numPfcpAssociationUpdateResponseTotalSentPerSec       int = 4040046
	numPfcpAssociationUpdateResponseTotalReceivedPerSec   int = 4040047
	numPfcpAssociationUpdateRequestTotalSentPerSec        int = 4040048
	numPfcpNodeReportRequestTotalReceivedPerSec           int = 4040049
	numPfcpNodeReportResponseTotalSentPerSec              int = 4040050
	numPfcpAssociationReleaseRequestTotalReceivedPerSec   int = 4040051
	numPfcpAssociationReleaseResponseTotalSentPerSec      int = 4040052
	numPfcpPFDManagementRequestTotalReceivedPerSec        int = 4040053
	numPfcpPFDManagementResponseTotalSentPerSec           int = 4040054
	numPfcpSessionEstablishmentRequestTotalReceivedPerSec int = 4040055
	numPfcpSessionEstablishmentResponseTotalSentPerSec    int = 4040056
	numPfcpSessionModificationRequestTotalReceivedPerSec  int = 4040057
	numPfcpSessionModificationResponseTotalSentPerSec     int = 4040058
	numPfcpSessionDeletionRequestTotalReceivedPerSec      int = 4040059
	numPfcpSessionDeletionResponseTotalSentPerSec         int = 4040060
	numPfcpSessionReportRequestTotalSentPerSec            int = 4040061
	numPfcpSessionReportResponseTotalReceivedPerSec       int = 4040062
	numEchoRequest                                        int = 4040063
	numEchoResponse                                       int = 4040064
	numEndMarksMessages                                   int = 4040065
)

func TestUpf() {
	num := [59]int64{}
	for i := 0; i < 59; i++ {
		num[i] = (int64(rand.Intn(100))) * 10
	}
	//pm.ClearCounter(UpfmoduleSet.TotalPackets)
	//pm.ClearCounter(UpfmoduleSet.TotalBits)
	//pm.ClearCounter(UpfmoduleSet.TotalDiscardedPackets)
	//pm.ClearCounter(UpfmoduleSet.UpLinkTotalPacketsSent)
	//pm.ClearCounter(UpfmoduleSet.UpLinkTotalPacketsReceived)
	//pm.ClearCounter(UpfmoduleSet.UpLinkTotalBitsSent)
	//pm.ClearCounter(UpfmoduleSet.UpLinkTotalBitsReceived)
	//pm.ClearCounter(UpfmoduleSet.UpLinkTotalReceivedPacketsDiscarded)
	//pm.ClearCounter(UpfmoduleSet.UpLinkTotalSentPacketsDiscarded)
	//pm.ClearCounter(UpfmoduleSet.UpLinkTotalInvalidPackets)
	//
	//pm.ClearCounter(UpfmoduleSet.UpLinkTotalDiscardedPackets)
	//pm.ClearCounter(UpfmoduleSet.DownLinkTotalPacketsSent)
	//pm.ClearCounter(UpfmoduleSet.DownLinkTotalPacketsReceived)
	//pm.ClearCounter(UpfmoduleSet.DownLinkTotalBitsSent)
	//pm.ClearCounter(UpfmoduleSet.DownLinkTotalBitsReceived)
	//pm.ClearCounter(UpfmoduleSet.DownLinkTotalReceivedPacketsDiscarded)
	//pm.ClearCounter(UpfmoduleSet.DownLinkTotalSentPacketsDiscarded)
	//pm.ClearCounter(UpfmoduleSet.DownLinkTotalInvalidPackets)
	//pm.ClearCounter(UpfmoduleSet.DownLinkTotalDiscardedPackets)

	pm.IncCounter(UpfmoduleSet.TotalPackets, num[0])
	pm.IncCounter(UpfmoduleSet.TotalBits, num[1])
	pm.IncCounter(UpfmoduleSet.TotalDiscardedPackets, num[2])
	pm.IncCounter(UpfmoduleSet.UpLinkTotalPacketsSent, num[3])
	pm.IncCounter(UpfmoduleSet.UpLinkTotalPacketsReceived, num[4])
	pm.IncCounter(UpfmoduleSet.UpLinkTotalBitsSent, num[5])
	pm.IncCounter(UpfmoduleSet.UpLinkTotalBitsReceived, num[6])
	pm.IncCounter(UpfmoduleSet.UpLinkTotalReceivedPacketsDiscarded, num[7])
	pm.IncCounter(UpfmoduleSet.UpLinkTotalSentPacketsDiscarded, num[8])
	pm.IncCounter(UpfmoduleSet.UpLinkTotalInvalidPackets, num[9])

	pm.IncCounter(UpfmoduleSet.UpLinkTotalDiscardedPackets, num[10])
	pm.IncCounter(UpfmoduleSet.DownLinkTotalPacketsSent, num[11])
	pm.IncCounter(UpfmoduleSet.DownLinkTotalPacketsReceived, num[12])
	pm.IncCounter(UpfmoduleSet.DownLinkTotalBitsSent, num[13])
	pm.IncCounter(UpfmoduleSet.DownLinkTotalBitsReceived, num[14])
	pm.IncCounter(UpfmoduleSet.DownLinkTotalReceivedPacketsDiscarded, num[15])
	pm.IncCounter(UpfmoduleSet.DownLinkTotalSentPacketsDiscarded, num[16])
	pm.IncCounter(UpfmoduleSet.DownLinkTotalInvalidPackets, num[17])
	pm.IncCounter(UpfmoduleSet.DownLinkTotalDiscardedPackets, num[18])

	pm.IncCounter(UpfmoduleSet.PFCPAssociationSetupResponseTotalSent, num[19])
	pm.IncCounter(UpfmoduleSet.PFCPAssociationSetupRequestTotalReceived, num[20])
	pm.IncCounter(UpfmoduleSet.HeartBeatRequestTotalReceived, num[21])
	pm.IncCounter(UpfmoduleSet.HeartBeatResponseTotalSent, num[22])
	pm.IncCounter(UpfmoduleSet.HeartBeatResponseTotalReceived, num[24])
	pm.IncCounter(UpfmoduleSet.HeartBeatRequestTotalSent, num[25])
	pm.IncCounter(UpfmoduleSet.PFCPAssociationUpdateRequestTotalReceived, num[26])
	pm.IncCounter(UpfmoduleSet.PFCPAssociationUpdateResponseTotalSent, num[27])
	pm.IncCounter(UpfmoduleSet.PFCPAssociationUpdateResponseTotalReceived, num[28])
	pm.IncCounter(UpfmoduleSet.PFCPAssociationUpdateRequestTotalSent, num[29])
	pm.IncCounter(UpfmoduleSet.PFCPNodeReportRequestTotalSent, num[30])
	pm.IncCounter(UpfmoduleSet.PFCPNodeReportResponseTotalReceived, num[31])
	pm.IncCounter(UpfmoduleSet.PFCPAssociationReleaseRequestTotalReceived, num[32])
	pm.IncCounter(UpfmoduleSet.PFCPAssociationReleaseResponseTotalSent, num[33])
	pm.IncCounter(UpfmoduleSet.PFCPPFDManagementRequestTotalReceived, num[34])
	pm.IncCounter(UpfmoduleSet.PFCPPFDManagementResponseTotalSent, num[35])
	pm.IncCounter(UpfmoduleSet.PFCPSessionEstablishmentRequestTotalReceived, num[36])
	pm.IncCounter(UpfmoduleSet.PFCPSessionEstablishmentResponseTotalSent, num[37])
	pm.IncCounter(UpfmoduleSet.PFCPSessionModificationRequestTotalReceived, num[38])
	pm.IncCounter(UpfmoduleSet.PFCPSessionModificationResponseTotalSent, num[39])
	pm.IncCounter(UpfmoduleSet.PFCPSessionDeletionRequestTotalReceived, num[40])
	pm.IncCounter(UpfmoduleSet.PFCPSessionDeletionResponseTotalSent, num[41])
	pm.IncCounter(UpfmoduleSet.PFCPSessionReportRequestTotalSent, num[42])
	pm.IncCounter(UpfmoduleSet.PFCPSessionReportResponseTotalReceived, num[43])
	//pm.IncCounter(UpfmodulePISet.TotalPacketsPerSec.Count(),num)
	//pm.IncCounter(UpfmoduleSet.TotalPackets,num)
	//pm.IncCounter(UpfmoduleSet.TotalPackets,num)
	pm.IncCounter(UpfmoduleSet.EchoRequest, num[44])
	pm.IncCounter(UpfmoduleSet.EchoResponse, num[45])
	pm.IncCounter(UpfmoduleSet.EndMarksMessages, num[46])
}
func ReportToLems(upfNo string) *webTypes.NfPerformanceData {
	pms := webTypes.NewNfPerformanceData()
	pms.NfName = upfNo
	//TestUpf()
	//pms.Params = append(pms.Params, webTypes.Param{111, 100})
	var params = make([]webTypes.Param, 0, 30)
	// upf module counter
	params = append(params, webTypes.Param{numTotalPackets, UpfmoduleSet.TotalPackets.Count()})
	params = append(params, webTypes.Param{numTotalBits, UpfmoduleSet.TotalBits.Count() * 8})
	params = append(params, webTypes.Param{numTotalDiscardedPackets, UpfmoduleSet.TotalDiscardedPackets.Count()})
	params = append(params, webTypes.Param{numUpLinkTotalPacketsSent, UpfmoduleSet.UpLinkTotalPacketsSent.Count()})
	params = append(params, webTypes.Param{numUpLinkTotalPacketsReceived, UpfmoduleSet.UpLinkTotalPacketsReceived.Count()})
	params = append(params, webTypes.Param{numUpLinkTotalBitsSent, UpfmoduleSet.UpLinkTotalBitsSent.Count() * 8})
	params = append(params, webTypes.Param{numUpLinkTotalBitsReceived, UpfmoduleSet.UpLinkTotalBitsReceived.Count() * 8})
	params = append(params, webTypes.Param{numUpLinkTotalReceivedPacketsDiscarded, UpfmoduleSet.UpLinkTotalReceivedPacketsDiscarded.Count()})
	params = append(params, webTypes.Param{numUpLinkTotalSentPacketsDiscarded, UpfmoduleSet.UpLinkTotalSentPacketsDiscarded.Count()})
	params = append(params, webTypes.Param{numUpLinkTotalInvalidPackets, UpfmoduleSet.UpLinkTotalInvalidPackets.Count()})

	params = append(params, webTypes.Param{numUpLinkTotalDiscardedPackets, UpfmoduleSet.UpLinkTotalDiscardedPackets.Count()})
	params = append(params, webTypes.Param{numDownLinkTotalPacketsSent, UpfmoduleSet.DownLinkTotalPacketsSent.Count()})
	params = append(params, webTypes.Param{numDownLinkTotalPacketsReceived, UpfmoduleSet.DownLinkTotalPacketsReceived.Count()})
	params = append(params, webTypes.Param{numDownLinkTotalBitsSent, UpfmoduleSet.DownLinkTotalBitsSent.Count() * 8})
	params = append(params, webTypes.Param{numDownLinkTotalBitsReceived, UpfmoduleSet.DownLinkTotalBitsReceived.Count() * 8})
	params = append(params, webTypes.Param{numDownLinkTotalReceivedPacketsDiscarded, UpfmoduleSet.DownLinkTotalReceivedPacketsDiscarded.Count()})
	params = append(params, webTypes.Param{numDownLinkTotalSentPacketsDiscarded, UpfmoduleSet.DownLinkTotalSentPacketsDiscarded.Count()})
	params = append(params, webTypes.Param{numDownLinkTotalInvalidPackets, UpfmoduleSet.DownLinkTotalInvalidPackets.Count()})
	params = append(params, webTypes.Param{numDownLinkTotalDiscardedPackets, UpfmoduleSet.DownLinkTotalDiscardedPackets.Count()})

	// upf module meter P-I
	params = append(params, webTypes.Param{numTotalPacketsSec, int64(UpfmodulePISet.TotalPacketsPerSec.Rate1())})
	params = append(params, webTypes.Param{numTotalBitsSec, int64(UpfmodulePISet.TotalBitsPerSec.Rate1())})
	params = append(params, webTypes.Param{numUpLinkPacketsSentSec, int64(UpfmodulePISet.UpLinkPacketsSentPerSec.Rate1())})
	params = append(params, webTypes.Param{numUpLinkPacketsReceivedSec, int64(UpfmodulePISet.UpLinkPacketsReceivedPerSec.Rate1())})
	params = append(params, webTypes.Param{numUpLinkBitsSentSec, int64(UpfmodulePISet.UpLinkBitsSentPerSec.Rate1())})
	params = append(params, webTypes.Param{numUpLinkBitsReceivedSec, int64(UpfmodulePISet.UpLinkBitsReceivedPerSec.Rate1())})
	params = append(params, webTypes.Param{numDownLinkPacketsSentSec, int64(UpfmodulePISet.DownLinkPacketsSentPerSec.Rate1())})
	params = append(params, webTypes.Param{numDownLinkPacketsReceivedSec, int64(UpfmodulePISet.DownLinkPacketsReceivedPerSec.Rate1())})
	params = append(params, webTypes.Param{numDownLinkBitsSentSec, int64(UpfmodulePISet.DownLinkBitsSentPerSec.Rate1())})
	params = append(params, webTypes.Param{numDownLinkBitsReceivedSec, int64(UpfmodulePISet.DownLinkBitsReceivedPerSec.Rate1())})

	//pfcp
	params = append(params, webTypes.Param{numPfcpAssociationSetupRequestTotalReceivedPerSec, UpfmodulePISet.PFCPAssociationSetupRequestTotalReceivedPerSec.Count()})
	params = append(params, webTypes.Param{numPfcpAssociationSetupResponseTotalSentPerSec, UpfmodulePISet.PFCPAssociationSetupResponseTotalSentPerSec.Count()})
	params = append(params, webTypes.Param{numHeartBeatRequestTotalReceivedPerSec, UpfmodulePISet.HeartBeatRequestTotalReceivedPerSec.Count()})
	params = append(params, webTypes.Param{numHeartBeatRequestTotalSentPerSec, UpfmodulePISet.HeartBeatRequestTotalSentPerSec.Count()})
	params = append(params, webTypes.Param{numHeartBeatResponseTotalReceivedPerSec, UpfmodulePISet.HeartBeatResponseTotalReceivedPerSec.Count()})
	params = append(params, webTypes.Param{numHeartBeatResponseTotalSentPerSec, UpfmodulePISet.HeartBeatResponseTotalSentPerSec.Count()})
	params = append(params, webTypes.Param{numPfcpAssociationUpdateRequestTotalReceivedPerSec, UpfmodulePISet.PFCPAssociationUpdateRequestTotalReceivedPerSec.Count()})
	params = append(params, webTypes.Param{numPfcpAssociationUpdateResponseTotalSentPerSec, UpfmodulePISet.PFCPAssociationUpdateResponseTotalSentPerSec.Count()})
	params = append(params, webTypes.Param{numPfcpAssociationUpdateResponseTotalReceivedPerSec, UpfmodulePISet.PFCPAssociationUpdateResponseTotalReceivedPerSec.Count()})
	params = append(params, webTypes.Param{numPfcpAssociationUpdateRequestTotalSentPerSec, UpfmodulePISet.PFCPAssociationUpdateRequestTotalSentPerSec.Count()})
	params = append(params, webTypes.Param{numPfcpNodeReportRequestTotalReceivedPerSec, UpfmodulePISet.PFCPNodeReportRequestTotalSentPerSec.Count()})
	params = append(params, webTypes.Param{numPfcpNodeReportResponseTotalSentPerSec, UpfmodulePISet.PFCPNodeReportRequestTotalSentPerSec.Count()})
	params = append(params, webTypes.Param{numPfcpAssociationReleaseRequestTotalReceivedPerSec, UpfmodulePISet.PFCPAssociationReleaseRequestTotalReceivedPerSec.Count()})
	params = append(params, webTypes.Param{numPfcpAssociationReleaseResponseTotalSentPerSec, UpfmodulePISet.PFCPAssociationReleaseResponseTotalSentPerSec.Count()})
	params = append(params, webTypes.Param{numPfcpPFDManagementRequestTotalReceivedPerSec, UpfmodulePISet.PFCPPFDManagementRequestTotalReceivedPerSec.Count()})
	params = append(params, webTypes.Param{numPfcpPFDManagementResponseTotalSentPerSec, UpfmodulePISet.PFCPPFDManagementResponseTotalSentPerSec.Count()})
	params = append(params, webTypes.Param{numPfcpSessionEstablishmentRequestTotalReceivedPerSec, UpfmodulePISet.PFCPSessionEstablishmentRequestReceivedPerSec.Count()})
	params = append(params, webTypes.Param{numPfcpSessionEstablishmentResponseTotalSentPerSec, UpfmodulePISet.PFCPSessionEstablishmentResponseSentPerSec.Count()})
	params = append(params, webTypes.Param{numPfcpSessionModificationRequestTotalReceivedPerSec, UpfmodulePISet.PFCPSessionModificationRequestReceivedPerSec.Count()})
	params = append(params, webTypes.Param{numPfcpSessionModificationResponseTotalSentPerSec, UpfmodulePISet.PFCPSessionModificationResponseSentPerSec.Count()})
	params = append(params, webTypes.Param{numPfcpSessionDeletionRequestTotalReceivedPerSec, UpfmodulePISet.PFCPSessionDeletionRequestReceivedPerSec.Count()})
	params = append(params, webTypes.Param{numPfcpSessionDeletionResponseTotalSentPerSec, UpfmodulePISet.PFCPSessionDeletionResponseSentPerSec.Count()})
	params = append(params, webTypes.Param{numPfcpSessionReportRequestTotalSentPerSec, UpfmodulePISet.PFCPSessionReportRequestSentPerSec.Count()})
	params = append(params, webTypes.Param{numPfcpSessionReportResponseTotalReceivedPerSec, UpfmodulePISet.PFCPSessionReportResponseReceivedPerSec.Count()})
	//n3
	params = append(params, webTypes.Param{numEchoRequest, UpfmodulePISet.EchoRequestPerSec.Count()})
	params = append(params, webTypes.Param{numEchoResponse, UpfmodulePISet.EchoResponsePerSec.Count()})
	params = append(params, webTypes.Param{numEndMarksMessages, UpfmodulePISet.EndMarksMessagesPerSec.Count()})
	pms.Params = params
	return pms
}

func UpfDiagnosis(ids webTypes.NfPmInquireReqData, nfname string) *webTypes.NfPerformanceData {
	pms := webTypes.NewNfPerformanceData()

	pms.NfName = nfname
	for _, id := range ids.IDs {
		switch id {
		case numTotalPackets:
			pms.Params = append(pms.Params, webTypes.Param{ParamId: numTotalPackets, ParamValue: UpfmoduleSet.TotalPackets.Count()})
		case numTotalBits:
			pms.Params = append(pms.Params, webTypes.Param{ParamId: numTotalBits, ParamValue: UpfmoduleSet.TotalBits.Count() * 8})
		case numTotalDiscardedPackets:
			pms.Params = append(pms.Params, webTypes.Param{ParamId: numTotalDiscardedPackets, ParamValue: UpfmoduleSet.TotalDiscardedPackets.Count()})
		case numUpLinkTotalPacketsSent:
			pms.Params = append(pms.Params, webTypes.Param{ParamId: numUpLinkTotalPacketsSent, ParamValue: UpfmoduleSet.UpLinkTotalPacketsSent.Count()})
		case numUpLinkTotalPacketsReceived:
			pms.Params = append(pms.Params, webTypes.Param{ParamId: numUpLinkTotalPacketsReceived, ParamValue: UpfmoduleSet.UpLinkTotalPacketsReceived.Count()})
		case numUpLinkTotalBitsSent:
			pms.Params = append(pms.Params, webTypes.Param{ParamId: numUpLinkTotalBitsSent, ParamValue: UpfmoduleSet.UpLinkTotalBitsSent.Count() * 8})
		case numUpLinkTotalBitsReceived:
			pms.Params = append(pms.Params, webTypes.Param{ParamId: numUpLinkTotalBitsReceived, ParamValue: UpfmoduleSet.UpLinkTotalBitsReceived.Count() * 8})
		case numUpLinkTotalReceivedPacketsDiscarded:
			pms.Params = append(pms.Params, webTypes.Param{ParamId: numUpLinkTotalReceivedPacketsDiscarded, ParamValue: UpfmoduleSet.UpLinkTotalReceivedPacketsDiscarded.Count()})
		case numUpLinkTotalSentPacketsDiscarded:
			pms.Params = append(pms.Params, webTypes.Param{ParamId: numUpLinkTotalSentPacketsDiscarded, ParamValue: UpfmoduleSet.UpLinkTotalSentPacketsDiscarded.Count()})
		case numUpLinkTotalInvalidPackets:
			pms.Params = append(pms.Params, webTypes.Param{ParamId: numUpLinkTotalInvalidPackets, ParamValue: UpfmoduleSet.UpLinkTotalInvalidPackets.Count()})
		case numUpLinkTotalDiscardedPackets:
			pms.Params = append(pms.Params, webTypes.Param{ParamId: numUpLinkTotalDiscardedPackets, ParamValue: UpfmoduleSet.UpLinkTotalDiscardedPackets.Count()})
		case numDownLinkTotalPacketsSent:
			pms.Params = append(pms.Params, webTypes.Param{ParamId: numDownLinkTotalPacketsSent, ParamValue: UpfmoduleSet.DownLinkTotalPacketsSent.Count()})
		case numDownLinkTotalPacketsReceived:
			pms.Params = append(pms.Params, webTypes.Param{ParamId: numDownLinkTotalPacketsReceived, ParamValue: UpfmoduleSet.DownLinkTotalPacketsReceived.Count()})
		case numDownLinkTotalBitsSent:
			pms.Params = append(pms.Params, webTypes.Param{ParamId: numDownLinkTotalBitsSent, ParamValue: UpfmoduleSet.DownLinkTotalBitsSent.Count() * 8})
		case numDownLinkTotalBitsReceived:
			pms.Params = append(pms.Params, webTypes.Param{ParamId: numDownLinkTotalBitsReceived, ParamValue: UpfmoduleSet.DownLinkTotalBitsReceived.Count() * 8})
		case numDownLinkTotalReceivedPacketsDiscarded:
			pms.Params = append(pms.Params, webTypes.Param{ParamId: numDownLinkTotalReceivedPacketsDiscarded, ParamValue: UpfmoduleSet.DownLinkTotalReceivedPacketsDiscarded.Count()})
		case numDownLinkTotalSentPacketsDiscarded:
			pms.Params = append(pms.Params, webTypes.Param{ParamId: numDownLinkTotalSentPacketsDiscarded, ParamValue: UpfmoduleSet.DownLinkTotalSentPacketsDiscarded.Count()})
		case numDownLinkTotalInvalidPackets:
			pms.Params = append(pms.Params, webTypes.Param{ParamId: numDownLinkTotalInvalidPackets, ParamValue: UpfmoduleSet.DownLinkTotalInvalidPackets.Count()})
		case numDownLinkTotalDiscardedPackets:
			pms.Params = append(pms.Params, webTypes.Param{ParamId: numDownLinkTotalDiscardedPackets, ParamValue: UpfmoduleSet.DownLinkTotalDiscardedPackets.Count()})
		case numTotalPacketsSec:
			pms.Params = append(pms.Params, webTypes.Param{ParamId: numTotalPacketsSec, ParamValue: int64(UpfmodulePISet.TotalPacketsPerSec.Rate1())})
		case numTotalBitsSec:
			pms.Params = append(pms.Params, webTypes.Param{ParamId: numTotalBitsSec, ParamValue: int64(UpfmodulePISet.TotalBitsPerSec.Rate1())})
		case numUpLinkPacketsSentSec:
			pms.Params = append(pms.Params, webTypes.Param{ParamId: numUpLinkPacketsSentSec, ParamValue: int64(UpfmodulePISet.UpLinkPacketsSentPerSec.Rate1())})
		case numUpLinkPacketsReceivedSec:
			pms.Params = append(pms.Params, webTypes.Param{ParamId: numUpLinkPacketsReceivedSec, ParamValue: int64(UpfmodulePISet.UpLinkPacketsReceivedPerSec.Rate1())})
		case numUpLinkBitsSentSec:
			pms.Params = append(pms.Params, webTypes.Param{ParamId: numUpLinkBitsSentSec, ParamValue: int64(UpfmodulePISet.UpLinkBitsSentPerSec.Rate1())})
		case numUpLinkBitsReceivedSec:
			pms.Params = append(pms.Params, webTypes.Param{ParamId: numUpLinkBitsReceivedSec, ParamValue: int64(UpfmodulePISet.UpLinkBitsReceivedPerSec.Rate1())})
		case numDownLinkPacketsSentSec:
			pms.Params = append(pms.Params, webTypes.Param{ParamId: numDownLinkPacketsSentSec, ParamValue: int64(UpfmodulePISet.DownLinkPacketsSentPerSec.Rate1())})
		case numDownLinkPacketsReceivedSec:
			pms.Params = append(pms.Params, webTypes.Param{ParamId: numDownLinkPacketsReceivedSec, ParamValue: int64(UpfmodulePISet.DownLinkPacketsReceivedPerSec.Rate1())})
		case numDownLinkBitsSentSec:
			pms.Params = append(pms.Params, webTypes.Param{ParamId: numDownLinkBitsSentSec, ParamValue: int64(UpfmodulePISet.DownLinkBitsSentPerSec.Rate1())})
		case numDownLinkBitsReceivedSec:
			pms.Params = append(pms.Params, webTypes.Param{ParamId: numDownLinkBitsReceivedSec, ParamValue: int64(UpfmodulePISet.DownLinkBitsReceivedPerSec.Rate1())})
		default:
			pms.Params = append(pms.Params, webTypes.Param{ParamValue: 0})
		}
	}
	return pms
}
