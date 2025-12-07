package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

type ProbeResult struct {
	Method  string
	Success bool
}

type HostResult struct {
	IP             string
	IsUp           bool
	Score          int
	TotalProbes    int
	Probes         []ProbeResult
	SuccessMethods []string
}

var (
	timeout     = 2 * time.Second
	tcpPorts    = []int{80, 443, 22, 445, 3389, 21, 25, 8080, 135, 139, 53, 5985, 1433, 3306, 5432, 6379, 88, 389}
	concurrency = 1
	verbose     = false
)

func main() {
	singleIP := flag.String("i", "", "Single IP to scan")
	ipRange := flag.String("r", "", "IP range in CIDR notation (e.g., 192.168.1.0/24)")
	listFile := flag.String("l", "", "File containing list of IPs")
	outputFile := flag.String("o", "", "Output results to file")
	verboseFlag := flag.Bool("v", false, "Verbose mode - show probe details")
	threads := flag.Int("t", 1, "Number of concurrent threads")
	timeoutFlag := flag.Int("to", 2, "Timeout in seconds")
	flag.Parse()

	timeout = time.Duration(*timeoutFlag) * time.Second
	concurrency = *threads
	verbose = *verboseFlag

	var ips []string

	if *singleIP != "" {
		ips = []string{*singleIP}
	} else if *ipRange != "" {
		ips = expandCIDR(*ipRange)
	} else if *listFile != "" {
		ips = readIPsFromFile(*listFile)
	} else {
		printBanner()
		flag.Usage()
		os.Exit(1)
	}

	if len(ips) == 0 {
		color.Red("✗ No valid IPs to scan")
		os.Exit(1)
	}

	printBanner()
	fmt.Println()

	results := scanHostsLive(ips, *outputFile)
	printSummary(results, verbose)
}

func printBanner() {
	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow)
	cyan := color.New(color.FgCyan)
	
	red.Println(`
 ██╗    ██╗██╗  ██╗ █████╗ ████████╗██╗ ██████╗  ██████╗ ████████╗
 ██║    ██║██║  ██║██╔══██╗╚══██╔══╝██║██╔════╝ ██╔═══██╗╚══██╔══╝
 ██║ █╗ ██║███████║███████║   ██║   ██║██║  ███╗██║   ██║   ██║   
 ██║███╗██║██╔══██║██╔══██║   ██║   ██║██║   ██║██║   ██║   ██║   
 ╚███╔███╔╝██║  ██║██║  ██║   ██║   ██║╚██████╔╝╚██████╔╝   ██║   
  ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   `)
	yellow.Println("        ⚡ Multi-Method Host Discovery Tool ⚡")
	cyan.Println("     [ ARP | ICMP | TCP ] - Can't hide from me! 🔍")
}

func expandCIDR(cidr string) []string {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		color.Red("✗ Invalid CIDR: %s", cidr)
		return nil
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
	}

	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}
	return ips
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func readIPsFromFile(filename string) []string {
	file, err := os.Open(filename)
	if err != nil {
		color.Red("✗ Cannot open file: %s", filename)
		return nil
	}
	defer file.Close()

	var ips []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			if strings.Contains(line, "/") {
				ips = append(ips, expandCIDR(line)...)
			} else {
				ips = append(ips, line)
			}
		}
	}
	return ips
}

func scanHostsLive(ips []string, outputFile string) []HostResult {
	total := len(ips)
	results := make([]HostResult, total)
	resultsChan := make(chan struct {
		idx    int
		result HostResult
	}, total)

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	// Print table header
	if verbose {
		fmt.Println("┌─────────────────┬────────┬───────┬──────────────────────────────────────────────────────────────────┐")
		color.Cyan("│ %-15s │ %-6s │ %-5s │ %-64s │\n", "IP", "STATUS", "SCORE", "METHODS")
		fmt.Println("├─────────────────┼────────┼───────┼──────────────────────────────────────────────────────────────────┤")
	} else {
		fmt.Println("┌─────────────────┬────────┬───────┐")
		color.Cyan("│ %-15s │ %-6s │ %-5s │\n", "IP", "STATUS", "SCORE")
		fmt.Println("├─────────────────┼────────┼───────┤")
	}

	// File for output
	var outFile *os.File
	if outputFile != "" {
		var err error
		outFile, err = os.Create(outputFile)
		if err != nil {
			color.Red("✗ Cannot create output file: %s", outputFile)
		}
	}

	// Printer goroutine
	var printWg sync.WaitGroup
	printWg.Add(1)
	go func() {
		defer printWg.Done()
		for item := range resultsChan {
			results[item.idx] = item.result
			r := item.result

			status := color.RedString("%-6s", "DOWN")
			statusPlain := "DOWN"
			if r.IsUp {
				status = color.GreenString("%-6s", "UP")
				statusPlain = "UP"
			}

			score := fmt.Sprintf("%d/%d", r.Score, r.TotalProbes)
			methods := strings.Join(r.SuccessMethods, ",")

			if verbose {
				fmt.Printf("│ %-15s │ %s │ %-5s │ %-64s │\n", r.IP, status, score, methods)
				if outFile != nil {
					fmt.Fprintf(outFile, "%s\t%s\t%s\t%s\n", r.IP, statusPlain, score, methods)
				}
			} else {
				fmt.Printf("│ %-15s │ %s │ %-5s │\n", r.IP, status, score)
				if outFile != nil {
					fmt.Fprintf(outFile, "%s\t%s\t%s\n", r.IP, statusPlain, score)
				}
			}
		}
	}()

	// Scanner goroutines
	for i, ip := range ips {
		wg.Add(1)
		go func(idx int, ipAddr string) {
			defer wg.Done()
			sem <- struct{}{}
			result := scanHost(ipAddr)
			<-sem
			resultsChan <- struct {
				idx    int
				result HostResult
			}{idx, result}
		}(i, ip)
	}

	wg.Wait()
	close(resultsChan)
	printWg.Wait()

	if outFile != nil {
		outFile.Close()
		fmt.Println()
		color.Yellow("✓ Results saved to: %s", outputFile)
	}

	return results
}

func scanHost(ip string) HostResult {
	result := HostResult{IP: ip, Probes: []ProbeResult{}}
	var wg sync.WaitGroup
	var mu sync.Mutex

	// ARP probe (works on local LAN)
	wg.Add(1)
	go func() {
		defer wg.Done()
		success := probeARP(ip)
		mu.Lock()
		result.Probes = append(result.Probes, ProbeResult{Method: "ARP", Success: success})
		mu.Unlock()
	}()

	// ICMP Ping probe
	wg.Add(1)
	go func() {
		defer wg.Done()
		success := probeICMP(ip)
		mu.Lock()
		result.Probes = append(result.Probes, ProbeResult{Method: "PING", Success: success})
		mu.Unlock()
	}()

	// TCP probes
	for _, port := range tcpPorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			success := probeTCP(ip, p)
			mu.Lock()
			result.Probes = append(result.Probes, ProbeResult{
				Method:  fmt.Sprintf("TCP:%d", p),
				Success: success,
			})
			mu.Unlock()
		}(port)
	}

	wg.Wait()

	for _, probe := range result.Probes {
		result.TotalProbes++
		if probe.Success {
			result.Score++
			result.SuccessMethods = append(result.SuccessMethods, probe.Method)
		}
	}
	result.IsUp = result.Score > 0
	return result
}

func probeICMP(ip string) bool {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("ping", "-n", "1", "-w", fmt.Sprintf("%d", int(timeout.Milliseconds())), ip)
	case "darwin":
		// macOS: -W is in milliseconds
		cmd = exec.Command("ping", "-c", "1", "-W", fmt.Sprintf("%d", int(timeout.Milliseconds())), ip)
	default:
		// Linux: -W is in seconds
		cmd = exec.Command("ping", "-c", "1", "-W", fmt.Sprintf("%d", int(timeout.Seconds())), ip)
	}
	err := cmd.Run()
	return err == nil
}

func probeTCP(ip string, port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		if opErr, ok := err.(*net.OpError); ok {
			if strings.Contains(opErr.Err.Error(), "refused") {
				return true
			}
		}
		return false
	}
	conn.Close()
	return true
}

func probeARP(ip string) bool {
	// Trigger ARP resolution by sending UDP packet
	conn, _ := net.DialTimeout("udp", fmt.Sprintf("%s:1", ip), 500*time.Millisecond)
	if conn != nil {
		conn.Close()
	}
	time.Sleep(200 * time.Millisecond)

	// Check ARP table for the IP
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("arp", "-a", ip)
	case "darwin":
		cmd = exec.Command("arp", "-n", ip)
	default:
		cmd = exec.Command("arp", "-n", ip)
	}

	output, err := cmd.Output()
	if err != nil {
		return false
	}

	outputStr := string(output)
	// Check if we got a valid MAC address (not incomplete)
	if strings.Contains(outputStr, "no entry") ||
		strings.Contains(outputStr, "incomplete") ||
		strings.Contains(outputStr, "(incomplete)") ||
		strings.Contains(outputStr, "no match") {
		return false
	}

	// Look for MAC address pattern (contains ":" or "-")
	if strings.Contains(outputStr, ":") || strings.Contains(outputStr, "-") {
		return true
	}

	return false
}

func printSummary(results []HostResult, isVerbose bool) {
	if isVerbose {
		fmt.Println("└─────────────────┴────────┴───────┴──────────────────────────────────────────────────────────────────┘")
	} else {
		fmt.Println("└─────────────────┴────────┴───────┘")
	}

	upCount := 0
	downCount := 0
	for _, r := range results {
		if r.IsUp {
			upCount++
		} else {
			downCount++
		}
	}
	fmt.Println()
	color.Green("● UP: %d", upCount)
	color.Red("● DOWN: %d", downCount)
}
