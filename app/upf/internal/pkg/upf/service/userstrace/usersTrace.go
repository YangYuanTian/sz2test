package userstrace

import (
	"fmt"
	"github.com/intel-go/nff-go/packet"
	"lite5gc/cmn/userstrace"
	"lite5gc/cmn/userstrace/trace"
	"lite5gc/oam/am"
	"lite5gc/upf/service/upfam"
	"os"
	"strings"
)

var cap = trace.NewCapture()

// Start 开始抓包函数
func Start() error {
	cap.Trace(packet.AllReceivedPackets, true)
	cap.Trace(packet.AbortPacket, true)
	cap.Trace(packet.ArpIcmp, true)
	cap.Trace(trace.ID("session_packet"), true)
	cap.UseTrace(true)
	if err := cap.Start(); err != nil {
		return err
	}
	//产生一个告警，方便去关闭抓包
	alarm := upfam.UPFAlarmDetails{
		AlarmID:    am.UPFCaptureStarted,
		Reason:     "UPF capture started",
		Suggestion: "remember to stop capture when you don't need it",
		Substring:  "0000",
	}
	upfam.UPFAlarmReport(alarm)
	return nil
}

func Stop() (ret error) {
	if err := userstrace.Stop(); err != nil {
		return err
	}
	//告警清除
	alarmDetails := upfam.UPFAlarmDetails{
		AlarmID:   am.UPFCaptureStarted,
		Reason:    "upf capture stopped",
		Substring: "0000",
	}
	upfam.UPFAlarmClear(alarmDetails)
	return nil
}

const (
	TurnOn         = "on"
	TurnOFF        = "off"
	Show           = "show"
	Clean          = "clean"
	CleanAll       = "cleanall"
	Trace          = "trace"
	Set            = "set"
	ShowCommandSep = ":"
	BufSize        = "bufSize"
	FileNum        = "fileNum"
	FileSize       = "fileSize"
)

// ParseTool return  1 and 2:3 in format string 1:2:3 which use separator ":"
func ParseTool(tool string) (toolName string, rest string) {
	toolAndCtl := strings.Split(tool, ShowCommandSep)
	if len(toolAndCtl) == 0 {
		return
	}
	toolName = toolAndCtl[0]
	if len(toolAndCtl) > 1 {
		rest = strings.Join(toolAndCtl[1:], ":")
	}
	return
}

func PcapClean(opt string, path string) (string, error) {
	if !cap.IsStop() {
		return fmt.Sprintf("please stop capture first,%s not allowed in capturing", opt), nil
	}
	if err := os.RemoveAll(path); err != nil {
		return "romove err:" + err.Error(), nil
	}
	return "remove success:" + path, nil
}

func parseTrace(fmtString string) (isTrace bool, id fmt.Stringer) {
	if len(fmtString) < 2 {
		return false, nil
	}
	if fmtString[0] == '-' {
		isTrace = true
		fmtString = fmtString[1:]
	}
	if fmtString[0] == 's' {
		var id packet.SEID
		if _, err := fmt.Sscanf(fmtString, "s%d", &id); err != nil {
			return false, nil
		}
		return !isTrace, id
	}
	if fmtString[0] == 't' {
		var id packet.TEID
		if _, err := fmt.Sscanf(fmtString, "t%d", &id); err != nil {
			return false, nil
		}
		return !isTrace, id
	}
	if strings.HasPrefix(fmtString, "UEIP_") ||
		strings.HasPrefix(fmtString, "SEID_") ||
		strings.HasPrefix(fmtString, "TEID_") ||
		strings.HasPrefix(fmtString, "DLTEID_") {
		return !isTrace, trace.ID(fmtString)
	}
	if strings.Count(fmtString, ".") == 3 {
		var id [4]byte
		if n, err := fmt.Sscanf(fmtString, "%d.%d.%d.%d", &id[0], &id[1], &id[2], &id[3]); n != 4 || err != nil {
			return false, nil
		}
		return !isTrace, packet.UEIP(id[:])
	}
	return !isTrace, trace.ID(fmtString)
}
