package main

import (
    "os"
    "github.com/FJ-cyberzilla/zillabreath/internal/core"
    "github.com/spf13/cobra"
)

func main() {
    var target string
    var output string
    
    var rootCmd = &cobra.Command{
        Use:   "zillabreath",
        Short: "zillabreath - Mobile Security Laboratory",
        Long: `zillabreath: Professional security testing platform for authorized research
		
Complete documentation: https://github.com/FJ-cyberzilla/zillabreath`,
        Run: func(cmd *cobra.Command, args []string) {
            if target == "" {
                cmd.Help()
                return
            }
            
            engine := core.NewEngine()
            engine.Scan(target)
        },
    }

    rootCmd.Flags().StringVarP(&target, "target", "t", "", "Target to scan (IP, hostname, or domain)")
    rootCmd.Flags().StringVarP(&output, "output", "o", "", "Output format (json, html, text)")
    
    if err := rootCmd.Execute(); err != nil {
        os.Exit(1)
    }
}
