package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var bfAnalysisCommand *cobra.Command

func init() {
	bfAnalysisCommand = &cobra.Command{
		Use:   "bruteforce_detection",
		Short: "Detecting brute force",
		Run:   bfAnalysis,
	}
	bfAnalysisCommand.Flags().StringP("filename", "f", "example.log", "Select log file..")
	bfAnalysisCommand.Flags().StringP("type", "t", "ssh", "Select your log type")
	bfAnalysisCommand.MarkFlagRequired("filename")
	bfAnalysisCommand.MarkFlagRequired("type")
}

func bfAnalysis(cmd *cobra.Command, args []string) {
	filename, _ := cmd.Flags().GetString("filename")
	language, _ := cmd.Flags().GetString("type")
	fmt.Printf("Starting to detect a brute force on %s [%s] file....", filename, language)
}

func main() {
	bfAnalysisCommand.Execute()
}
