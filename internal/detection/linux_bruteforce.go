package detection

import (
	"bufio"
	"fmt"
	"io"
	"os"

	"github.com/arianenda/bruteforce_detection/internal/parser"
)

func bruteForceDetection(file *os.File) {
	linuxLog := map[string]parser.LinuxAuthLog{}
	fileReader := bufio.NewReader(file)

	for {
		line, err := fileReader.ReadString('\n')
		parseLine := parser.parseLogLine(line)
		if value, ok := linuxLog[parseLine.srcIP]; ok {
			value.bruteForceCount += 1
			linuxLog[parseLine.srcIP] = value
		} else {
			linuxLog[parseLine.srcIP] = parseLine
		}
		if err == io.EOF {
			break
		}
	}

	for ip, log := range linuxLog {
		if log.bruteForceCount >= parser.MAX_COUNT {
			fmt.Printf("Possible brute force attacks from IP: %s with %d login attempts", ip, log.bruteForceCount)
		}
	}
}
