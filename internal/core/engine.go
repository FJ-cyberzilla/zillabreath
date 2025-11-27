package core

import (
    "time"
    
    "github.com/FJ-cyberzilla/zillabreath/internal/scanner"
    "github.com/FJ-cyberzilla/zillabreath/internal/analyzer"
)

type Engine struct {
    scanner  *scanner.SecurityScanner
    analyzer *analyzer.ThreatAnalyzer
    ui       *ui.TerminalUI
}

func NewEngine() *Engine {
    return &Engine{
        scanner:  scanner.New(),
        analyzer: analyzer.New(),
        ui:       ui.New(),
    }
}

func (e *Engine) Scan(target string) {
    startTime := time.Now()
    
    e.ui.ShowBanner()
    e.ui.ShowScanStart(target, "Comprehensive Security Assessment")
    
    // Phase 1: Network Discovery
    e.ui.ShowProgress("Network discovery and DNS resolution")
    networkResults := e.scanner.ScanNetwork(target)
    time.Sleep(500 * time.Millisecond)
    
    // Phase 2: Port Scanning
    e.ui.ShowProgress("Port scanning and service detection")
    portResults := e.scanner.ScanPorts(target)
    time.Sleep(500 * time.Millisecond)
    
    // Phase 3: System Analysis
    e.ui.ShowProgress("System information gathering")
    systemInfo := e.scanner.GetSystemInfo()
    time.Sleep(300 * time.Millisecond)
    
    // Phase 4: Threat Analysis
    e.ui.ShowProgress("Security analysis and risk assessment")
    threats := e.analyzer.Analyze(networkResults, portResults, systemInfo)
    time.Sleep(400 * time.Millisecond)
    
    // Phase 5: Results
    e.ui.ShowResults(threats)
    e.ui.ShowScanComplete(time.Since(startTime))
}
