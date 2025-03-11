package parser

import (
	"log"
	"os"
	"strconv"

	"github.com/beevik/etree"
)

type WindowsLog struct {
	EventId         int64
	TargetUsername  string
	IpAddress       string
	BruteForceCount int
}

const (
	EVENTID = 4625
	COUNT   = 3
)

func ParsingWindowsLogEvent(event *etree.Element) WindowsLog {
	logData := WindowsLog{}
	systemParent := event.SelectElement("System")
	eventDataParent := event.SelectElement("EventData")

	eventID, err := strconv.ParseInt(systemParent.SelectElement("EventID").Text(), 0, 64)
	if err != nil {
		panic(err)
	}

	if systemParent == nil && eventDataParent == nil {
		log.Fatalf("Couldn't parsing windows log event due to uncompatible format")
		os.Exit(-1)
	}

	if eventID != EVENTID {
		return logData
	}

	for _, data := range eventDataParent.SelectElements("Data") {
		switch data.SelectAttrValue("Name", "unknown") {
		case "TargetUsername":
			logData.TargetUsername = data.Text()
		case "IpAddress":
			logData.IpAddress = data.Text()
		default:
			break
		}
	}

	logData.EventId = eventID

	return logData

}
