package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ANSI color codes
const (
	red    = "\033[91m"
	yellow = "\033[93m"
	green  = "\033[92m"
	blue   = "\033[94m"
	cyan   = "\033[96m"
	reset  = "\033[0m"
)

// Shodan Internetdb JSON response structs
type ShodanResponse struct {
	IP        string   `json:"ip"`
	Hostnames []string `json:"hostnames"`
	Ports     []int    `json:"ports"`
	Vulns     []string `json:"vulns"`
}

// Shodan CVE database JSON response struct
type CveDetails struct {
	Summary string  `json:"summary"`
	CvssV3  float64 `json:"cvss_v3"`
}

// getSeverityColor determines the severity level based on the CVSS score.
func getSeverityColor(cvssScore float64) string {
	if cvssScore >= 9.0 {
		return fmt.Sprintf("%s[CRITICAL]%s", red, reset)
	} else if cvssScore >= 7.0 {
		return fmt.Sprintf("%s[HIGH]%s", red, reset)
	} else if cvssScore >= 4.0 {
		return fmt.Sprintf("%s[MEDIUM]%s", yellow, reset)
	}
	return fmt.Sprintf("%s[LOW]%s", green, reset)
}

// fetchCveDetails fetches CVE details from cvedb.shodan.io.
func fetchCveDetails(cveID string) (*CveDetails, error) {
	url := fmt.Sprintf("https://cvedb.shodan.io/cve/%s", cveID)
	time.Sleep(10 * time.Microsecond)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CVE details for %s: %v", cveID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch CVE details for %s, status: %s", cveID, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body for %s: %v", cveID, err)
	}

	var cveDetails CveDetails
	err = json.Unmarshal(body, &cveDetails)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON for %s: %v", cveID, err)
	}

	return &cveDetails, nil
}

// logResults prints the reconnaissance findings.
func logResults(ip string, data *ShodanResponse, showCVEs, showPorts, showHosts, showCVEPorts bool) {
	timestamp := fmt.Sprintf("%s[INFO]%s", yellow, reset)
	var logLines []string

	// Check for empty or invalid IP
	if ip == "" {
		return
	}

	// Default behavior if no flags are set
	if !showCVEs && !showPorts && !showHosts && !showCVEPorts {
		showPorts = true
		showCVEs = true
		showHosts = true
	}

	// Show open ports
	if showPorts && len(data.Ports) > 0 {
		portsStr := make([]string, len(data.Ports))
		for i, port := range data.Ports {
			portsStr[i] = fmt.Sprintf("%s%d%s", green, port, reset)
		}
		logLines = append(logLines, fmt.Sprintf("%s %s[%s]%s [PORTS: %s]", timestamp, blue, ip, reset, strings.Join(portsStr, ", ")))
	}

	// Show hostnames
	if showHosts && len(data.Hostnames) > 0 {
		hostsStr := make([]string, len(data.Hostnames))
		for i, host := range data.Hostnames {
			hostsStr[i] = fmt.Sprintf("%s%s%s", green, host, reset)
		}
		logLines = append(logLines, fmt.Sprintf("%s %s[%s]%s [HOSTNAMES: %s]", timestamp, blue, ip, reset, strings.Join(hostsStr, ", ")))
	}

	// Show CVEs with details, potentially with ports
	if (showCVEs || showCVEPorts) && len(data.Vulns) > 0 {
		cveChannel := make(chan struct {
			cveID      string
			cveDetails *CveDetails
			err        error
		})

		for _, cve := range data.Vulns {
			go func(cveID string) {
				details, err := fetchCveDetails(cveID)
				cveChannel <- struct {
					cveID      string
					cveDetails *CveDetails
					err        error
				}{cveID, details, err}
			}(cve)
		}

		for range data.Vulns {
			result := <-cveChannel
			if result.err != nil {
				fmt.Printf("%s[ERROR]%s Failed to fetch CVE details for %s: %v\n", red, reset, result.cveID, result.err)
				continue
			}

			severity := getSeverityColor(result.cveDetails.CvssV3)
			description := result.cveDetails.Summary
			if len(description) > 80 {
				description = description[:80]
			}

			portsStr := ""
			if showCVEPorts && len(data.Ports) > 0 {
				ports := make([]string, len(data.Ports))
				for i, port := range data.Ports {
					ports[i] = fmt.Sprintf("%s%d%s", green, port, reset)
				}
				portsStr = fmt.Sprintf(" [PORTS: %s]", strings.Join(ports, ", "))
			}

			logLines = append(logLines, fmt.Sprintf("%s %s[%s]%s [%s%s%s] %s [%s%s%s]%s", timestamp, blue, ip, reset, green, result.cveID, reset, severity, green, description, reset, portsStr))
		}
	}

	for _, line := range logLines {
		fmt.Println(line)
	}
}

// processIP fetches and displays information for a single IP address.
func processIP(ip string, showCVEs, showPorts, showHosts, showCVEPorts bool) {
	url := fmt.Sprintf("https://internetdb.shodan.io/%s", ip)
	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("%s[ERROR]%s Failed to fetch data for %s: %v\n", red, reset, ip, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return // Silently ignore 404 Not Found errors
	} else if resp.StatusCode != http.StatusOK {
		fmt.Printf("%s[ERROR]%s Failed to fetch data for %s, status: %s\n", red, reset, ip, resp.Status)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("%s[ERROR]%s Failed to read response body for %s: %v\n", red, reset, ip, err)
		return
	}

	var data ShodanResponse
		err = json.Unmarshal(body, &data)
		if err != nil {
			fmt.Printf("%s[ERROR]%s Failed to parse JSON for %s: %v\n", red, reset, ip, err)
			return
		}

		logResults(ip, &data, showCVEs, showPorts, showHosts, showCVEPorts)
	}

func main() {
	// Define command-line flags
	ipFlag := flag.String("ip", "", "Single IP to scan")
	fileFlag := flag.String("file", "", "File containing a list of IPs")
	showCVEs := flag.Bool("cves", false, "Show CVEs")
	showPorts := flag.Bool("ports", false, "Show open ports")
	showHosts := flag.Bool("host", false, "Show hostnames")
	showCVEPorts := flag.Bool("cve+ports", false, "Show CVEs with severity level and open ports")
	concurrencyFlag := flag.Int("c", 10, "Number of concurrent IP scans (default 10)")

	flag.Parse()

	// Create a channel for IP addresses and a WaitGroup
	ipChan := make(chan string)
	var wg sync.WaitGroup

	// Start worker goroutines
	for i := 0; i < *concurrencyFlag; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range ipChan {
				processIP(ip, *showCVEs, *showPorts, *showHosts, *showCVEPorts)
			}
		}()
	}

	// Function to send IPs to the channel
	sendIPs := func(scanner *bufio.Scanner) {
		for scanner.Scan() {
			ip := strings.TrimSpace(scanner.Text())
			if ip != "" {
				ipChan <- ip
			}
		}
		if err := scanner.Err(); err != nil {
			log.Fatalf("Failed to read input: %v", err)
		}
		close(ipChan)
	}

	// Check if any specific flags were provided
	if *ipFlag != "" {
		fmt.Printf("%s[INFO]%s Target: %s\n", yellow, reset, *ipFlag)
		ipChan <- *ipFlag
		close(ipChan)
	} else if *fileFlag != "" {
		fmt.Printf("%s[INFO]%s Target File: %s\n", yellow, reset, *fileFlag)
		file, err := os.Open(*fileFlag)
		if err != nil {
			log.Fatalf("Failed to open file: %v", err)
		}
		defer file.Close()
		sendIPs(bufio.NewScanner(file))
	} else {
		// Check if data is being piped to stdin
		stat, _ := os.Stdin.Stat()
		isPiped := (stat.Mode() & os.ModeCharDevice) == 0

		if isPiped {
			fmt.Printf("%s[INFO]%s Reading IPs from stdin...\n", yellow, reset)
			sendIPs(bufio.NewScanner(os.Stdin))
		} else {
			// No flags or piped input, display usage help
			fmt.Printf("%s[ERROR]%s No input specified.\n\n", red, reset)
			flag.Usage()
			os.Exit(1)
		}
	}

	// Wait for all workers to finish
	wg.Wait()

	fmt.Printf("\n%s[INFO]%s Scan Completed\n", yellow, reset)
}
