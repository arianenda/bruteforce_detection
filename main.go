package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"

	"github.com/spf13/cobra"
)

var validLogTypes = []string{
	"windows",
	"linux",
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
	fileUpload, err := os.Open(filePath)
	if err != nil {
		fmt.Println("Error opening file", err)
		os.Exit(-1)
	}

	if filepath.Ext(filename) != ".xml" || filepath.Ext(filename) != ".txt" && filepath.Ext(filename) != ".log" {
		fmt.Print("File format unsupported")
		os.Exit(-1)
	}

	defer fileUpload.Close()

	logType, _ := cmd.Flags().GetString("type")
	if slices.Contains(validLogTypes, logType) == false {
		log.Fatalf("Invalid use of type %s, please use one of %v", logType, validLogTypes)
	}

	fmt.Printf("Starting to detect a brute force on %s [%s] file....", filename, logType)
}

func main() {
	bfAnalysisCommand.Execute()
}
