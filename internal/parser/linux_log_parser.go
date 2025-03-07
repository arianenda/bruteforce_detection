package parser

import (
	"fmt"
	"os"
	"strings"
)

type LinuxAuthLog struct {
	SrcIP           string
	SrcPort         string
	BruteForceCount int
	Username        string
}

const (
	SSH              = "sshd"
	FAILURE_INFO     = "Failed password"
	MAX_COUNT        = 5
	NOT_INVALID_USER = "invalid"
)

func ParseLogLine(logline string) LinuxAuthLog {
	logInfo := LinuxAuthLog{}
	logLine := string(logline)

	if strings.Contains(logLine, SSH) && strings.Contains(logLine, FAILURE_INFO) && !strings.Contains(logLine, NOT_INVALID_USER) {
		splitAfterFor := strings.Split(logLine, "for")

		if len(splitAfterFor) < 2 {
			fmt.Printf("Unable to parsing the log")
			os.Exit(-1)
		}

		strInfo := strings.Split(splitAfterFor[1], " ")
		if len(strInfo) != 7 {
			return logInfo
		}

		logInfo.SrcIP = strInfo[3]
		logInfo.SrcPort = strInfo[5]
		logInfo.Username = strInfo[1]
	}

	return logInfo
}
