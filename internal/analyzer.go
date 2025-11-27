package analyzer

import (
    "github.com/FJ-cyberzilla/zillabreath/internal/scanner"
)

type ThreatAnalyzer struct{}

func New() *ThreatAnalyzer {
    return &ThreatAnalyzer{}
}

func (a *ThreatAnalyzer) Analyze(network scanner.NetworkInfo, ports []scanner.PortInfo, system scanner.SystemInfo) []Vulnerability {
    var vulnerabilities []Vulnerability
    
    for _, port := range ports {
        if port.State == "open" {
            risk, description, remediation := a.analyzePort(port)
            vulnerabilities = append(vulnerabilities, Vulnerability{
                Type:        "Open Service",
                Risk:        risk,
                Description: description,
                Remediation: remediation,
                Component:   a.getServiceComponent(port.Service),
                Reference:   a.getServiceReference(port.Service),
            })
        }
    }
    
    sysVulns := a.analyzeSystem(system)
    vulnerabilities = append(vulnerabilities, sysVulns...)
    
    return vulnerabilities
}

func (a *ThreatAnalyzer) analyzePort(port scanner.PortInfo) (string, string, string) {
    portAnalysis := map[int]struct {
        risk        string
        description string
        remediation string
    }{
        21: {
            risk:        "High",
            description: "FTP service exposed - credentials transmitted in cleartext",
            remediation: "Disable FTP or migrate to SFTP/FTPS",
        },
        22: {
            risk:        "Medium", 
            description: "SSH service accessible - ensure strong authentication",
            remediation: "Use key-based authentication, disable password auth",
        },
        23: {
            risk:        "Critical",
            description: "Telnet service exposed - completely unencrypted",
            remediation: "Immediately disable Telnet, use SSH instead",
        },
        80: {
            risk:        "Low",
            description: "HTTP web service running",
            remediation: "Implement HTTPS redirect, security headers",
        },
        443: {
            risk:        "Low", 
            description: "HTTPS web service running",
            remediation: "Ensure TLS 1.2+, valid certificate, secure ciphers",
        },
        53: {
            risk:        "Medium",
            description: "DNS service exposed",
            remediation: "Restrict DNS queries, implement DNSSEC",
        },
        8080: {
            risk:        "Medium",
            description: "HTTP proxy/alternative service",
            remediation: "Authenticate access, implement WAF",
        },
        8443: {
            risk:        "Medium",
            description: "HTTPS alternative service",
            remediation: "Same security as port 443",
        },
    }
    
    if analysis, exists := portAnalysis[port.Port]; exists {
        return analysis.risk, analysis.description, analysis.remediation
    }
    
    return "Low", "Unknown service exposed", "Investigate service purpose and secure accordingly"
}

func (a *ThreatAnalyzer) getServiceComponent(service string) string {
    components := map[string]string{
        "ftp":        "File Transfer",
        "ssh":        "Remote Access", 
        "telnet":     "Remote Access",
        "http":       "Web Service",
        "https":      "Web Service",
        "dns":        "Network Service",
        "http-proxy": "Proxy Service",
        "https-alt":  "Web Service",
    }
    
    if component, exists := components[service]; exists {
        return component
    }
    return "Network Service"
}

func (a *ThreatAnalyzer) getServiceReference(service string) string {
    references := map[string]string{
        "ftp":    "CWE-319: Cleartext Transmission",
        "ssh":    "CIS SSH Benchmark",
        "telnet": "CWE-319: Cleartext Transmission", 
        "http":   "OWASP Top 10",
        "https":  "OWASP TLS Guidelines",
    }
    
    if ref, exists := references[service]; exists {
        return ref
    }
    return "Best Practices"
}

func (a *ThreatAnalyzer) analyzeSystem(system scanner.SystemInfo) []Vulnerability {
    var vulns []Vulnerability
    
    if system.OS == "android" {
        vulns = append(vulns, Vulnerability{
            Type:        "Mobile Device",
            Risk:        "Info",
            Description: "Scanning Android-based mobile device",
            Remediation: "Ensure device encryption, regular updates, app permissions",
            Component:   "Operating System",
            Reference:   "Android Security Guidelines",
        })
    }
    
    vulns = append(vulns, Vulnerability{
        Type:        "System Architecture",
        Risk:        "Info", 
        Description: "System information gathered for assessment",
        Remediation: "Regular security updates and monitoring",
        Component:   "Platform",
        Reference:   "System Hardening Guidelines",
    })
    
    return vulns
}

type Vulnerability struct {
    Type        string
    Risk        string
    Description string
    Remediation string
    Component   string
    Reference   string
}
import (
    "fmt"
    "strings"
    "time"
    "github.com/FJ-cyberzilla/zillabreath/internal/analyzer"
    "github.com/fatih/color"
)

type TerminalUI struct {
    success *color.Color
    error   *color.Color
    warning *color.Color
    info    *color.Color
    cyan    *color.Color
    magenta *color.Color
    bold    *color.Color
}

func New() *TerminalUI {
    return &TerminalUI{
        success: color.New(color.FgGreen, color.Bold),
        error:   color.New(color.FgRed, color.Bold),
        warning: color.New(color.FgYellow, color.Bold),
        info:    color.New(color.FgCyan),
        cyan:    color.New(color.FgCyan, color.Bold),
        magenta: color.New(color.FgMagenta, color.Bold),
        bold:    color.New(color.Bold),
    }
}

func (ui *TerminalUI) ShowBanner() {
    // Create gradient effect using different colors
    banner := []string{
        "================================================================================",
        "",
        "  ########################################################",
        "  ##  ######  #  ##       ##          #####  ######  ##  ##",
        "  ##     ##   #  ##       ##          ##  ##  ##  ##  ##  ##",
        "  ##    ##    #  ##       ##          #####   ######  ######",
        "  ##   ##     #  ##       ##          ##  ##  ##  ##  ##  ##",
        "  ##  ######  #  ######   ######      #####   ##  ##  ##  ##",
        "  ########################################################",
        "",
        "               Mobile Security Laboratory",
        "                   zillabreath / ジラブレス",
        "",
        "================================================================================",
        "",
    }

    // Animated color gradient banner
    colors := []*color.Color{
        color.New(color.FgCyan, color.Bold),
        color.New(color.FgBlue, color.Bold),
        color.New(color.FgMagenta, color.Bold),
        color.New(color.FgCyan, color.Bold),
    }

    for i, line := range banner {
        colorIndex := i % len(colors)
        colors[colorIndex].Println(line)
        time.Sleep(30 * time.Millisecond)
    }

    // System info
    ui.info.Printf("  Version: 1.0.0 | Build: %s\n", time.Now().Format("2006-01-02"))
    ui.info.Println("  Repository: github.com/FJ-cyberzilla/topgear")
    fmt.Println()
}

func (ui *TerminalUI) Info(format string, args ...interface{}) {
    ui.info.Printf("[i] "+format+"\n", args...)
}

func (ui *TerminalUI) Success(format string, args ...interface{}) {
    ui.success.Printf("[✓] "+format+"\n", args...)
}

func (ui *TerminalUI) Error(format string, args ...interface{}) {
    ui.error.Printf("[✗] "+format+"\n", args...)
}

func (ui *TerminalUI) Warning(format string, args ...interface{}) {
    ui.warning.Printf("[!] "+format+"\n", args...)
}

func (ui *TerminalUI) ShowProgress(message string) {
    ui.cyan.Printf("[~] %s...\n", message)
}

func (ui *TerminalUI) ShowSeparator() {
    fmt.Println(strings.Repeat("─", 80))
}

func (ui *TerminalUI) ShowHeader(title string) {
    ui.ShowSeparator()
    ui.bold.Printf("  %s\n", title)
    ui.ShowSeparator()
}

func (ui *TerminalUI) ShowResults(threats []analyzer.Vulnerability) {
    fmt.Println()
    ui.ShowHeader("SECURITY ASSESSMENT RESULTS")
    fmt.Println()
    
    if len(threats) == 0 {
        ui.Success("No security vulnerabilities detected")
        ui.info.Println("  System appears to be secure based on current scan parameters")
        fmt.Println()
        return
    }
    
    // Group threats by risk level
    riskGroups := make(map[string][]analyzer.Vulnerability)
    for _, threat := range threats {
        riskGroups[threat.Risk] = append(riskGroups[threat.Risk], threat)
    }
    
    // Display summary
    ui.ShowSummary(len(threats), riskGroups)
    fmt.Println()
    
    // Display detailed findings
    ui.ShowHeader("DETAILED FINDINGS")
    fmt.Println()
    
    riskOrder := []string{"Critical", "High", "Medium", "Low", "Info"}
    counter := 1
    
    for _, risk := range riskOrder {
        if vulnerabilities, exists := riskGroups[risk]; exists {
            for _, threat := range vulnerabilities {
                ui.ShowVulnerabilityDetail(counter, threat)
                counter++
            }
        }
    }
    
    fmt.Println()
    ui.ShowFooter()
}

func (ui *TerminalUI) ShowSummary(total int, riskGroups map[string][]analyzer.Vulnerability) {
    ui.bold.Println("  Summary:")
    ui.info.Printf("  Total Vulnerabilities Found: %d\n", total)
    fmt.Println()
    
    riskColors := map[string]*color.Color{
        "Critical": color.New(color.FgRed, color.Bold),
        "High":     color.New(color.FgRed),
        "Medium":   color.New(color.FgYellow, color.Bold),
        "Low":      color.New(color.FgYellow),
        "Info":     color.New(color.FgCyan),
    }
    
    riskOrder := []string{"Critical", "High", "Medium", "Low", "Info"}
    for _, risk := range riskOrder {
        if count := len(riskGroups[risk]); count > 0 {
            c := riskColors[risk]
            c.Printf("  [%s] %s: %d\n", getRiskSymbol(risk), risk, count)
        }
    }
}

func (ui *TerminalUI) ShowVulnerabilityDetail(index int, threat analyzer.Vulnerability) {
    // Risk level coloring
    var riskColor *color.Color
    switch threat.Risk {
    case "Critical":
        riskColor = color.New(color.FgRed, color.Bold, color.BgWhite)
    case "High":
        riskColor = color.New(color.FgRed, color.Bold)
    case "Medium":
        riskColor = color.New(color.FgYellow, color.Bold)
    case "Low":
        riskColor = color.New(color.FgYellow)
    default:
        riskColor = color.New(color.FgCyan)
    }
    
    fmt.Printf("\n")
    ui.bold.Printf("  [%d] ", index)
    fmt.Printf("%s\n", threat.Type)
    
    fmt.Printf("      Risk Level:   ")
    riskColor.Printf("%s %s\n", getRiskSymbol(threat.Risk), threat.Risk)
    
    fmt.Printf("      Description:  %s\n", threat.Description)
    
    if threat.Remediation != "" {
        ui.success.Printf("      Remediation:  %s\n", threat.Remediation)
    }
    
    // Add affected component if available
    if threat.Component != "" {
        ui.info.Printf("      Component:    %s\n", threat.Component)
    }
    
    // Add CVE or reference if available
    if threat.Reference != "" {
        ui.cyan.Printf("      Reference:    %s\n", threat.Reference)
    }
}

func (ui *TerminalUI) ShowFooter() {
    ui.ShowSeparator()
    ui.info.Println("  Scan completed. Review findings and apply recommended remediations.")
    ui.info.Println("  For detailed reports, use the --output flag.")
    ui.ShowSeparator()
}

func (ui *TerminalUI) ShowScanStart(target string, scanType string) {
    fmt.Println()
    ui.ShowHeader(fmt.Sprintf("INITIATING %s SCAN", strings.ToUpper(scanType)))
    ui.info.Printf("  Target:    %s\n", target)
    ui.info.Printf("  Started:   %s\n", time.Now().Format("2006-01-02 15:04:05"))
    ui.info.Printf("  Scan Type: %s\n", scanType)
    fmt.Println()
}

func (ui *TerminalUI) ShowScanComplete(duration time.Duration) {
    fmt.Println()
    ui.success.Printf("Scan completed in %s\n", duration.Round(time.Millisecond))
    fmt.Println()
}

func getRiskSymbol(risk string) string {
    symbols := map[string]string{
        "Critical": "███",
        "High":     "██",
        "Medium":   "█",
        "Low":      "▓",
        "Info":     "░",
    }
    
    if symbol, exists := symbols[risk]; exists {
        return symbol
    }
    return "■"
}

func (ui *TerminalUI) ShowTable(headers []string, rows [][]string) {
    if len(rows) == 0 {
        ui.Warning("No data to display")
        return
    }
    
    // Calculate column widths
    colWidths := make([]int, len(headers))
    for i, header := range headers {
        colWidths[i] = len(header)
    }
    
    for _, row := range rows {
        for i, cell := range row {
            if i < len(colWidths) && len(cell) > colWidths[i] {
                colWidths[i] = len(cell)
            }
        }
    }
    
    // Print header
    fmt.Println()
    ui.bold.Print("  ")
    for i, header := range headers {
        ui.bold.Printf("%-*s", colWidths[i]+3, header)
    }
    fmt.Println()
    
    // Print separator
    fmt.Print("  ")
    for _, width := range colWidths {
        fmt.Print(strings.Repeat("─", width+3))
    }
    fmt.Println()
    
    // Print rows
    for _, row := range rows {
        fmt.Print("  ")
        for i, cell := range row {
            if i < len(colWidths) {
                fmt.Printf("%-*s", colWidths[i]+3, cell)
            }
        }
        fmt.Println()
    }
    fmt.Println()
}

func (ui *TerminalUI) Prompt(question string) string {
    ui.cyan.Printf("[?] %s: ", question)
    var response string
    fmt.Scanln(&response)
    return response
}

func (ui *TerminalUI) ShowSpinner(message string, done chan bool) {
    spinners := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
    i := 0
    
    for {
        select {
        case <-done:
            fmt.Print("\r")
            return
        default:
            ui.cyan.Printf("\r  %s %s", spinners[i%len(spinners)], message)
            time.Sleep(100 * time.Millisecond)
            i++
        }
    }
}
