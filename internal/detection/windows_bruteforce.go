package detection

import (
	"fmt"

	"github.com/arianenda/bruteforce_detection/internal/parser"
	"github.com/beevik/etree"
)

func WindowsBruteForceDetection(file *etree.Document) {
	bruteForceLog := map[string]parser.WindowsLog{}
	root := file.SelectElement("Events")
	for _, event := range root.SelectElements("Event") {
		parsingEvent := parser.ParsingWindowsLogEvent(event)

		if value, ok := bruteForceLog[parsingEvent.IpAddress]; ok {
			value.BruteForceCount += 1
			bruteForceLog[parsingEvent.IpAddress] = value
		} else {
			parsingEvent.BruteForceCount = 1
			bruteForceLog[parsingEvent.IpAddress] = parsingEvent
		}
	}

	fmt.Println("Map:", bruteForceLog)

	for ip, log := range bruteForceLog {
		if log.BruteForceCount >= parser.COUNT && log.IpAddress != "" {
			fmt.Printf("Possible brute force attacks from IP: %s with %d login attempts\n", ip, log.BruteForceCount)
		}
	}
}
