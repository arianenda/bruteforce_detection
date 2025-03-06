package parser

import "strings"

type LinuxAuthLog struct {
	SrcIP           string
	SrcPort         string
	BruteForceCount int
	Username        string
}

const (
	SSH          = "sshd"
	FAILURE_INFO = "Failed password"
	MAX_COUNT    = 5
)

func ParseLogLine(logline string) LinuxAuthLog {
	logInfo := LinuxAuthLog{}
	logLine := string(logline)

	if strings.Contains(logLine, SSH) && strings.Contains(logLine, FAILURE_INFO) {
		splitAfterFor := strings.Split(logLine, "for")
		strInfo := strings.Split(splitAfterFor[1], " ")
		logInfo.SrcIP = strInfo[3]
		logInfo.SrcPort = strInfo[5]
		logInfo.Username = strInfo[1]
	}

	return logInfo
}
