package scanner

import (
    "net"
    "os"
    "runtime"
    "time"
    
    "github.com/FJ-cyberzilla/zillabreath/internal/ui"
)

type SecurityScanner struct {
    ui *ui.TerminalUI
}

func New() *SecurityScanner {
    return &SecurityScanner{
        ui: ui.New(),
    }
}

func (s *SecurityScanner) ScanNetwork(target string) NetworkInfo {
    s.ui.ShowProgress("Performing network discovery")
    
    addrs, err := net.LookupHost(target)
    if err != nil {
        s.ui.Error("DNS lookup failed: %v", err)
        return NetworkInfo{}
    }
    
    localIP := getLocalIP()
    hostname, _ := os.Hostname()
    
    s.ui.Success("Discovered %d IP addresses for %s", len(addrs), target)
    
    return NetworkInfo{
        IPAddresses: addrs,
        Hostname:    hostname,
        LocalIP:     localIP,
        Timestamp:   time.Now(),
    }
}

func (s *SecurityScanner) ScanPorts(target string) []PortInfo {
    s.ui.ShowProgress("Scanning network ports")
    
    commonPorts := []int{21, 22, 23, 53, 80, 443, 8080, 8443}
    var openPorts []PortInfo
    
    s.ui.Info("Testing %d common ports on %s", len(commonPorts), target)
    
    for _, port := range commonPorts {
        if s.isPortOpen(target, port) {
            service := s.getServiceName(port)
            openPorts = append(openPorts, PortInfo{
                Port:      port,
                State:     "open",
                Service:   service,
                Protocol:  "tcp",
                Timestamp: time.Now(),
            })
            s.ui.Success("Discovered open port: %d/%s", port, service)
        }
    }
    
    s.ui.Info("Port scan complete: %d open ports found", len(openPorts))
    return openPorts
}

func (s *SecurityScanner) isPortOpen(host string, port int) bool {
    timeout := time.Second * 2
    conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, string(rune(port))), timeout)
    if err != nil {
        return false
    }
    defer conn.Close()
    return true
}

func (s *SecurityScanner) getServiceName(port int) string {
    services := map[int]string{
        21:   "ftp",
        22:   "ssh",
        23:   "telnet",
        53:   "dns",
        80:   "http",
        443:  "https",
        8080: "http-proxy",
        8443: "https-alt",
    }
    
    if service, exists := services[port]; exists {
        return service
    }
    return "unknown"
}

func (s *SecurityScanner) GetSystemInfo() SystemInfo {
    host, _ := os.Hostname()
    localIP := getLocalIP()
    
    return SystemInfo{
        OS:           runtime.GOOS,
        Architecture: runtime.GOARCH,
        Hostname:     host,
        LocalIP:      localIP,
        Timestamp:    time.Now(),
    }
}

func getLocalIP() string {
    addrs, err := net.InterfaceAddrs()
    if err != nil {
        return ""
    }
    
    for _, addr := range addrs {
        if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
            if ipnet.IP.To4() != nil {
                return ipnet.IP.String()
            }
        }
    }
    return ""
}

type NetworkInfo struct {
    IPAddresses []string
    Hostname    string
    LocalIP     string
    Timestamp   time.Time
}

type PortInfo struct {
    Port      int
    State     string
    Service   string
    Protocol  string
    Timestamp time.Time
}

type SystemInfo struct {
    OS           string
    Architecture string
    Hostname     string
    LocalIP      string
    Timestamp    time.Time
}
