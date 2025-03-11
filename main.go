package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"

	"github.com/arianenda/bruteforce_detection/internal/detection"
	"github.com/beevik/etree"
	"github.com/spf13/cobra"
)

var validLogTypes = []string{
	"windows",
	"linux",
}

var validFileFormat = []string{
	".log",
	".xml",
	".txt",
}

var bfAnalysisCommand *cobra.Command

func init() {
	bfAnalysisCommand = &cobra.Command{
		Use:   "bruteforce_detection",
		Short: "Detecting brute force",
		Run:   bfAnalysis,
	}
	bfAnalysisCommand.Flags().StringP("filename", "f", "example.log", "Select log file..")
	bfAnalysisCommand.Flags().StringP("type", "t", "linux", "Select your log type")
	bfAnalysisCommand.MarkFlagRequired("filename")
	bfAnalysisCommand.MarkFlagRequired("type")
}

func bfAnalysis(cmd *cobra.Command, args []string) {
	filename, _ := cmd.Flags().GetString("filename")
	filePath := "samples/" + filename
	fileExtension := filepath.Ext(filename)
	logType, _ := cmd.Flags().GetString("type")

	if slices.Contains(validFileFormat, fileExtension) == false {
		log.Fatalf("Invalid use of file format %s, file formats are allowed: %v", fileExtension, validFileFormat)
	}

	if slices.Contains(validLogTypes, logType) == false {
		log.Fatalf("Invalid use of type %s, please use one of %v", logType, validLogTypes)
	}

	switch logType {
	case "linux":
		fileUpload, err := os.Open(filePath)

		if err != nil {
			fmt.Println("Error opening file", err)
			os.Exit(-1)
		}

		defer fileUpload.Close()
		detection.BruteForce(fileUpload)
	case "windows":
		doc := etree.NewDocument()
		if err := doc.ReadFromFile(filePath); err != nil {
			log.Fatalf("Error reading XML file: %v", err)
		}

		detection.WindowsBruteForceDetection(doc)
	default:
		log.Fatalf("Unknown file types")
	}

	fmt.Printf("Starting to detect a brute force on %s [%s] file....\n", filename, logType)

}

func main() {
	bfAnalysisCommand.Execute()
}
