package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
)

// ─── Config ───────────────────────────────────────────────────────────────────

const (
	workers          = 10             // параллельных воркеров
	threadsPerWorker = 1000           // потоков на каждый воркер (итого 10,000)
	checkTimeout     = 8 * time.Second
	checkSite        = "https://www.google.com"
	output           = "valid.txt"
)

// ─── Sources ──────────────────────────────────────────────────────────────────

const (
	fmtText     = "text"
	fmtGeonode  = "geonode"
	fmtJSONList = "json_list"
	fmtHTML     = "html"
)

type Source struct {
	name   string
	url    string
	format string
}

var sources = []Source{
	{"ErcinDedeoglu",       "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/socks5.txt", fmtText},
	{"proxyscrape_v2",      "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000&country=all&anonymity=all&simplified=true", fmtText},
	{"proxyscrape_v2_disp", "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5", fmtText},
	{"proxyscrape_v3",      "https://api.proxyscrape.com/v3/free-proxy-list/get?request=getproxies&protocol=socks5", fmtText},
	{"geonode",             "https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&protocols=socks5&anonymityLevel=elite&anonymityLevel=anonymous", fmtGeonode},
	{"r00tee",              "https://raw.githubusercontent.com/r00tee/Proxy-List/main/Socks5.txt", fmtText},
	{"Anonym0usWork1221",   "https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/refs/heads/main/proxy_files/socks5_proxies.txt", fmtText},
	{"openproxylist",       "https://openproxylist.xyz/socks5.txt", fmtText},
	{"ObcbO",               "https://raw.githubusercontent.com/ObcbO/getproxy/refs/heads/master/file/socks5.txt", fmtText},
	{"TheSpeedX",           "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/socks5.txt", fmtText},
	{"TuanMinPay",          "https://raw.githubusercontent.com/TuanMinPay/live-proxy/refs/heads/master/socks5.txt", fmtText},
	{"databay-labs",        "https://raw.githubusercontent.com/databay-labs/free-proxy-list/refs/heads/master/socks5.txt", fmtText},
	{"dinoz0rg",            "https://raw.githubusercontent.com/dinoz0rg/proxy-list/refs/heads/main/checked_proxies/socks5.txt", fmtText},
	{"dpangestuw",          "https://raw.githubusercontent.com/dpangestuw/Free-PROXY/refs/heads/main/socks5_proxies.txt", fmtText},
	{"ebrasha",             "https://raw.githubusercontent.com/ebrasha/abdal-proxy-hub/refs/heads/main/socks5-proxy-list-by-EbraSha.txt", fmtText},
	{"hookzof",             "https://raw.githubusercontent.com/hookzof/socks5_list/refs/heads/master/proxy.txt", fmtText},
	{"hproxy-com",          "https://raw.githubusercontent.com/hproxy-com/free-proxy-list/refs/heads/main/socks5.txt", fmtText},
	{"iplocate",            "https://raw.githubusercontent.com/iplocate/free-proxy-list/refs/heads/main/protocols/socks5.txt", fmtText},
	{"mauricegift",         "https://raw.githubusercontent.com/mauricegift/free-proxies/refs/heads/master/files/socks5.json", fmtJSONList},
	{"proxifly",            "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/socks5/data.txt", fmtText},
	{"roosterkid",          "https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/SOCKS5_RAW.txt", fmtText},
	{"sunny9577",           "https://raw.githubusercontent.com/sunny9577/proxy-scraper/refs/heads/master/generated/socks5_proxies.txt", fmtText},
	{"z3a4",                "https://raw.githubusercontent.com/z3a4/free-proxy-list/refs/heads/main/proxies/checked/protocols/socks5/socks5-proxies.txt", fmtText},
	{"zloi-user",           "https://raw.githubusercontent.com/zloi-user/hideip.me/refs/heads/main/socks5.txt", fmtText},
	{"socks-proxy.net",     "https://socks-proxy.net/", fmtHTML},
}

type GeonodeResp struct {
	Data []struct {
		IP   string `json:"ip"`
		Port string `json:"port"`
	} `json:"data"`
}

// ─── Worker stats ─────────────────────────────────────────────────────────────

type WorkerStat struct {
	total   uint64
	checked uint64
	valid   uint64
	active  int64
}

// ─── Exporter ─────────────────────────────────────────────────────────────────

type Exporter struct {
	mu   sync.Mutex
	file *os.File
}

func newExporter(path string) *Exporter {
	f, _ := os.Create(path)
	return &Exporter{file: f}
}

func (e *Exporter) save(p string) {
	e.mu.Lock()
	fmt.Fprintln(e.file, p)
	e.mu.Unlock()
}

// ─── Fetch (параллельно) ──────────────────────────────────────────────────────

func fetchAll() []string {
	ch := make(chan []string, len(sources))
	for _, s := range sources {
		s := s
		go func() { ch <- fetchSource(s) }()
	}
	seen := make(map[string]struct{})
	var all []string
	for range sources {
		for _, p := range <-ch {
			if _, ok := seen[p]; !ok {
				seen[p] = struct{}{}
				all = append(all, p)
			}
		}
	}
	return all
}

var reIPPort = regexp.MustCompile(`\b(\d{1,3}\.){3}\d{1,3}:\d{2,5}\b`)

func fetchSource(s Source) []string {
	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequest("GET", s.url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("  ✗ %-20s %v\n", s.name, err)
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var proxies []string
	switch s.format {
	case fmtGeonode:
		var gr GeonodeResp
		json.Unmarshal(body, &gr)
		for _, d := range gr.Data {
			if d.IP != "" && d.Port != "" {
				proxies = append(proxies, d.IP+":"+d.Port)
			}
		}
	case fmtJSONList:
		// Generic JSON array of objects with ip/port fields
		var items []map[string]interface{}
		if err := json.Unmarshal(body, &items); err == nil {
			for _, item := range items {
				ip := fmt.Sprintf("%v", item["ip"])
				port := fmt.Sprintf("%v", item["port"])
				if ip != "<nil>" && port != "<nil>" && ip != "" && port != "" {
					proxies = append(proxies, ip+":"+port)
				}
			}
		}
	case fmtHTML:
		for _, m := range reIPPort.FindAllString(string(body), -1) {
			proxies = append(proxies, m)
		}
	default: // fmtText
		sc := bufio.NewScanner(strings.NewReader(string(body)))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			line = strings.TrimPrefix(line, "socks5://")
			if line != "" && strings.Contains(line, ":") && !strings.HasPrefix(line, "#") {
				proxies = append(proxies, line)
			}
		}
	}
	fmt.Printf("  ✓ %-20s %d\n", s.name, len(proxies))
	return proxies
}

// ─── Proxy check ──────────────────────────────────────────────────────────────

func checkProxy(p string) bool {
	dialer, err := proxy.SOCKS5("tcp", p, nil, &net.Dialer{Timeout: checkTimeout})
	if err != nil {
		return false
	}
	tr := &http.Transport{
		Dial:                  dialer.Dial,
		TLSHandshakeTimeout:   checkTimeout,
		ResponseHeaderTimeout: checkTimeout,
		DisableKeepAlives:     true,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   checkTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest("GET", checkSite, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode < 500
}

// ─── Worker ───────────────────────────────────────────────────────────────────

func runWorker(id int, chunk []string, exp *Exporter, stat *WorkerStat) {
	atomic.StoreUint64(&stat.total, uint64(len(chunk)))
	sem := make(chan struct{}, threadsPerWorker)
	var wg sync.WaitGroup

	for _, p := range chunk {
		p := p
		sem <- struct{}{}
		wg.Add(1)
		atomic.AddInt64(&stat.active, 1)

		go func() {
			defer func() {
				<-sem
				wg.Done()
				atomic.AddInt64(&stat.active, -1)
				atomic.AddUint64(&stat.checked, 1)
			}()

			if checkProxy(p) {
				atomic.AddUint64(&stat.valid, 1)
				exp.save(p)
			}
		}()
	}
	wg.Wait()
}

// ─── Split list ───────────────────────────────────────────────────────────────

func splitN(list []string, n int) [][]string {
	chunks := make([][]string, n)
	size := (len(list) + n - 1) / n
	for i := range chunks {
		lo := i * size
		hi := lo + size
		if hi > len(list) {
			hi = len(list)
		}
		if lo < len(list) {
			chunks[i] = list[lo:hi]
		}
	}
	return chunks
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	fmt.Println("╔══════════════════════════════════════════════════════╗")
	fmt.Printf("║  SOCKS5 Checker  │  %d workers × %d threads = %d total  ║\n",
		workers, threadsPerWorker, workers*threadsPerWorker)
	fmt.Printf("║  Timeout: %s  │  Target: %-22s  ║\n", checkTimeout, checkSite)
	fmt.Println("╚══════════════════════════════════════════════════════╝")

	// ── Download ──
	fmt.Println("\n[*] Downloading sources...")
	all := fetchAll()
	fmt.Printf("\n[*] Total unique: %d → splitting into %d chunks\n\n", len(all), workers)

	exp := newExporter(output)
	chunks := splitN(all, workers)
	stats := make([]*WorkerStat, workers)
	for i := range stats {
		stats[i] = &WorkerStat{}
	}

	// ── Live stats ──
	go func() {
		for range time.Tick(time.Second) {
			fmt.Printf("\033[%dA", workers+2)

			var totTotal, totChecked, totValid uint64
			for i, s := range stats {
				total   := atomic.LoadUint64(&s.total)
				checked := atomic.LoadUint64(&s.checked)
				valid   := atomic.LoadUint64(&s.valid)
				active  := atomic.LoadInt64(&s.active)

				pct := 0.0
				if total > 0 {
					pct = float64(checked) / float64(total) * 100
				}

				barLen := 20
				filled := int(pct / 100 * float64(barLen))
				bar := strings.Repeat("█", filled) + strings.Repeat("░", barLen-filled)

				fmt.Printf("  W%-2d [%s] %5.1f%%  \033[32m✓%d\033[0m  %d/%d  thr:%d\n",
					i+1, bar, pct, valid, checked, total, active)

				totTotal   += total
				totChecked += checked
				totValid   += valid
			}

			totPct := 0.0
			if totTotal > 0 {
				totPct = float64(totChecked) / float64(totTotal) * 100
			}
			fmt.Printf("  ─────────────────────────────────────────────────────\n")
			fmt.Printf("  TOTAL  %d/%d (%.1f%%)  \033[32mVALID: %d\033[0m  → %s\n",
				totChecked, totTotal, totPct, totValid, output)
		}
	}()

	for i := 0; i < workers+2; i++ {
		fmt.Println()
	}

	start := time.Now()
	var wg sync.WaitGroup
	for i, chunk := range chunks {
		if len(chunk) == 0 {
			continue
		}
		wg.Add(1)
		go func(id int, chunk []string, stat *WorkerStat) {
			defer wg.Done()
			runWorker(id, chunk, exp, stat)
		}(i, chunk, stats[i])
	}
	wg.Wait()
	exp.file.Close()

	elapsed := time.Since(start)
	var totalValid uint64
	for _, s := range stats {
		totalValid += atomic.LoadUint64(&s.valid)
	}

	fmt.Printf("\n\n[✓] Done in %.1fs  Valid: %d/%d → %s\n",
		elapsed.Seconds(), totalValid, len(all), output)
}
