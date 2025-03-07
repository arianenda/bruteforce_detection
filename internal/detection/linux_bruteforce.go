package detection

import (
	"bufio"
	"fmt"
	"io"
	"os"

	"github.com/arianenda/bruteforce_detection/internal/parser"
)

func BruteForce(file *os.File) {
	linuxLog := map[string]parser.LinuxAuthLog{}
	fileReader := bufio.NewReader(file)

	for {
		line, err := fileReader.ReadString('\n')
		parseLine := parser.ParseLogLine(line)

		if value, ok := linuxLog[parseLine.SrcIP]; ok {
			value.BruteForceCount += 1
			linuxLog[parseLine.SrcIP] = value
		} else {
			linuxLog[parseLine.SrcIP] = parseLine
		}
		if err == io.EOF {
			break
		}
	}

	for ip, log := range linuxLog {
		if log.BruteForceCount >= parser.MAX_COUNT && log.SrcIP != "" {
			fmt.Printf("Possible brute force attacks from IP: %s with %d login attempts", ip, log.BruteForceCount)
		}
	}
}
