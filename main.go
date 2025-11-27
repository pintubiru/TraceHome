package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

// --- CONFIGURATION ---
var (
	InterfaceName string
	AppPort       string
	TelegramToken string
	TelegramChat  string
	RouterDNS     string

	ScanInterval   = 15 * time.Second
	OfflineTimeout = 3 * time.Minute
	// Period to ignore rapid disconnect/reconnect events to avoid notification spam
	SnoozeWindow = 5 * time.Minute

	DataFile    = "users.json"
	LogFile     = "logs.json"
	UnknownFile = "unknown_history.json"
)

// --- DATA STRUCTURES ---
type User struct {
	Name          string    `json:"name"`
	MAC           string    `json:"mac"`
	IP            string    `json:"ip"`
	Vendor        string    `json:"vendor"`
	Hostname      string    `json:"hostname"`
	Group         string    `json:"group"`
	Notify        bool      `json:"notify"`
	LastSeen      time.Time `json:"last_seen"`
	Status        string    `json:"status"`
	MinutesAgo    int       `json:"minutes_ago"`
	PossibleMatch string    `json:"possible_match,omitempty"`
}

type UnknownDevice struct {
	MAC       string    `json:"mac"`
	IP        string    `json:"ip"`
	Vendor    string    `json:"vendor"`
	Hostname  string    `json:"hostname"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Count     int       `json:"count"`
}

type LogEntry struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	MAC       string    `json:"mac"`
	Name      string    `json:"name"`
	Action    string    `json:"action"`
	Detail    string    `json:"detail"`
}

type ScannedDevice struct {
	IP       string
	MAC      string
	Vendor   string
	Hostname string
}

var (
	users           = []User{}
	activityLogs    = []LogEntry{}
	unknownHistory  = make(map[string]UnknownDevice)
	lastScanDevices = []ScannedDevice{}
	mutex           sync.RWMutex
)

// --- MAIN ENTRY POINT ---
func main() {
	// Attempt to load .env for local development convenience; ignore if missing (e.g., in Docker/Prod)
	if err := godotenv.Load(); err != nil {
		log.Println("⚠️ Warning: .env file not found, using system environment variables.")
	}

	InterfaceName = strings.TrimSpace(os.Getenv("NETWORK_INTERFACE"))
	if InterfaceName == "" {
		InterfaceName = "eth0"
	}
	AppPort = strings.TrimSpace(os.Getenv("APP_PORT"))
	if AppPort == "" {
		AppPort = "1234"
	}
	TelegramToken = strings.TrimSpace(os.Getenv("TELEGRAM_BOT_TOKEN"))
	TelegramChat = strings.TrimSpace(os.Getenv("TELEGRAM_CHAT_ID"))
	RouterDNS = strings.TrimSpace(os.Getenv("ROUTER_DNS"))

	if TelegramToken == "" || TelegramChat == "" {
		log.Println("⚠️ WARNING: Telegram credentials are missing. Notifications will not be sent.")
	}

	// Initial data load does not require locking as the server hasn't started yet
	if err := loadUsers(); err != nil {
		log.Printf("Info: %v", err)
	}
	if err := loadLogs(); err != nil {
		log.Printf("Info: %v", err)
	}
	if err := loadUnknownHistory(); err != nil {
		log.Printf("Info: %v", err)
	}

	// Run background tasks concurrently
	go startScanner()
	go startTimeoutChecker()

	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	r.LoadHTMLGlob("templates/*")

	// View Routes
	r.GET("/", func(c *gin.Context) { c.HTML(http.StatusOK, "index.html", nil) })
	r.GET("/details/:mac", func(c *gin.Context) { c.HTML(http.StatusOK, "detail.html", gin.H{"mac": c.Param("mac")}) })
	r.GET("/unknowns", func(c *gin.Context) { c.HTML(http.StatusOK, "unknowns.html", nil) })

	// API Routes
	r.GET("/api/status", handleGetStatus)
	r.GET("/api/logs/:mac", handleGetLogs)
	r.GET("/api/unknowns", handleGetUnknownHistory)
	r.POST("/api/register", handleRegister)
	r.DELETE("/api/users/:mac", handleDeleteUser)
	r.POST("/api/test-telegram", handleTestTelegram)

	log.Printf("🔥 Monitor Ready: %s | Port %s", InterfaceName, AppPort)
	if err := r.Run(":" + AppPort); err != nil {
		log.Fatal("❌ Server Crash/Exit: ", err)
	}
}

// --- UTILITIES ---
func normalizeMAC(mac string) string {
	return strings.ToLower(strings.TrimSpace(mac))
}

// --- HTTP HANDLERS ---

func handleTestTelegram(c *gin.Context) {
	if TelegramToken == "" || TelegramChat == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Telegram token is not configured in .env"})
		return
	}
	// Run in background to avoid blocking the HTTP response
	go func() {
		err := sendTelegram("🔔 <b>Notification Test</b>\nMonitoring system is running correctly!")
		if err != nil {
			log.Printf("❌ Failed to send test telegram: %v", err)
		} else {
			log.Println("✅ Test telegram sent successfully.")
		}
	}()
	c.JSON(http.StatusOK, gin.H{"message": "Test message is being sent..."})
}

func handleGetUnknownHistory(c *gin.Context) {
	mutex.RLock()
	defer mutex.RUnlock()

	var list []UnknownDevice
	// Filter out transient devices (detected only once) to reduce noise
	for _, dev := range unknownHistory {
		if dev.Count >= 2 {
			list = append(list, dev)
		}
	}

	sort.Slice(list, func(i, j int) bool {
		return list[i].LastSeen.After(list[j].LastSeen)
	})

	c.JSON(http.StatusOK, list)
}

func handleRegister(c *gin.Context) {
	var req User
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	targetMAC := normalizeMAC(req.MAC)

	mutex.Lock()
	defer mutex.Unlock()

	updated := false
	for i, u := range users {
		if u.MAC == targetMAC {
			users[i].Name = req.Name
			users[i].Group = req.Group
			users[i].Notify = req.Notify
			// Only update hostname if provided, otherwise preserve existing
			if req.Hostname != "" {
				users[i].Hostname = req.Hostname
			}
			updated = true
			break
		}
	}

	if !updated {
		newUser := User{
			Name: req.Name, MAC: targetMAC,
			IP: req.IP, Vendor: req.Vendor, Hostname: req.Hostname,
			Group: req.Group, Notify: req.Notify,
			LastSeen: time.Now(), Status: "ONLINE",
		}
		users = append(users, newUser)
	}

	// Remove from unknown history once registered to keep the unknown list clean
	if _, exists := unknownHistory[targetMAC]; exists {
		delete(unknownHistory, targetMAC)
		saveUnknownHistory()
	}

	if err := saveUsers(); err != nil {
		log.Printf("Error saving users: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save data"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Data saved successfully"})
}

func handleDeleteUser(c *gin.Context) {
	mac := normalizeMAC(c.Param("mac"))

	mutex.Lock()
	defer mutex.Unlock()

	found := false
	for i, u := range users {
		if u.MAC == mac {
			// Efficient slice deletion
			users = append(users[:i], users[i+1:]...)
			found = true
			break
		}
	}

	if found {
		if err := saveUsers(); err != nil {
			log.Printf("Error saving users after delete: %v", err)
		}
		c.JSON(http.StatusOK, gin.H{"message": "Deleted"})
	} else {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
	}
}

func handleGetStatus(c *gin.Context) {
	mutex.RLock()
	defer mutex.RUnlock()
	now := time.Now()

	knownUsers := make([]User, len(users))
	copy(knownUsers, users)
	for i := range knownUsers {
		diff := now.Sub(knownUsers[i].LastSeen)
		knownUsers[i].MinutesAgo = int(diff.Minutes())
		// Fallback to Vendor if Hostname is empty for better UI display
		if knownUsers[i].Hostname == "" {
			knownUsers[i].Hostname = knownUsers[i].Vendor
		}
	}

	unknownList := []User{}
	for _, scanned := range lastScanDevices {
		isKnown := false
		for _, user := range users {
			if user.MAC == scanned.MAC {
				isKnown = true
				break
			}
		}

		if !isKnown {
			// Logic to suggest possible owner based on hostname or timing
			possibleOwner := ""
			matchReason := ""
			if scanned.Hostname != "" {
				for _, u := range users {
					if strings.EqualFold(u.Hostname, scanned.Hostname) {
						possibleOwner = u.Name
						matchReason = "(Same Hostname)"
						break
					}
					// Fuzzy matching for similar hostnames (e.g. "iPhone-User" vs "iPhone")
					if u.Hostname != "" && len(u.Hostname) > 4 &&
						(strings.Contains(strings.ToLower(scanned.Hostname), strings.ToLower(u.Hostname)) ||
							strings.Contains(strings.ToLower(u.Hostname), strings.ToLower(scanned.Hostname))) {
						possibleOwner = u.Name
						matchReason = "(Similar Hostname)"
						break
					}
				}
			}
			// Heuristic: If a known device just went offline and an unknown device appears from the same vendor, it might be the same device randomized MAC
			if possibleOwner == "" {
				for _, u := range users {
					if u.Status == "OFFLINE" {
						if now.Sub(u.LastSeen) < 2*time.Minute {
							vendorMatch := true
							if scanned.Vendor != "Unknown" && u.Vendor != "Unknown" && u.Vendor != "" {
								v1 := strings.ToLower(scanned.Vendor)
								v2 := strings.ToLower(u.Vendor)
								if !strings.Contains(v1, v2) && !strings.Contains(v2, v1) {
									vendorMatch = false
								}
							}
							if vendorMatch {
								possibleOwner = u.Name
								matchReason = "(Just went Offline)"
								break
							}
						}
					}
				}
			}
			finalMatchMsg := ""
			if possibleOwner != "" {
				finalMatchMsg = fmt.Sprintf("%s %s", possibleOwner, matchReason)
			}

			unknownList = append(unknownList, User{
				Name: "Unknown", MAC: scanned.MAC, IP: scanned.IP,
				Vendor: scanned.Vendor, Hostname: scanned.Hostname,
				Status: "ONLINE", Group: "Unknown", PossibleMatch: finalMatchMsg,
			})
		}
	}
	c.JSON(http.StatusOK, gin.H{"known": knownUsers, "unknown": unknownList})
}

func handleGetLogs(c *gin.Context) {
	mac := normalizeMAC(c.Param("mac"))
	mutex.RLock()
	defer mutex.RUnlock()

	var userInfo User
	found := false
	for _, u := range users {
		if u.MAC == mac {
			userInfo = u
			found = true
			break
		}
	}
	if !found {
		userInfo = User{Name: "Unknown", MAC: mac}
	}

	userLogs := []LogEntry{}
	for _, l := range activityLogs {
		if l.MAC == mac {
			userLogs = append(userLogs, l)
		}
	}
	sort.Slice(userLogs, func(i, j int) bool { return userLogs[i].Timestamp.After(userLogs[j].Timestamp) })
	c.JSON(http.StatusOK, gin.H{"user": userInfo, "logs": userLogs})
}

// --- NETWORK SCANNER ---

func startScanner() {
	ticker := time.NewTicker(ScanInterval)
	defer ticker.Stop()
	for range ticker.C {
		// Using CombinedOutput to capture stderr for easier debugging of arp-scan failures
		cmd := exec.Command("arp-scan", "-I", InterfaceName, "--localnet", "--ignoredups", "--retry=2")
		output, err := cmd.CombinedOutput()

		if err != nil {
			log.Printf("⚠️ ARP Scan Error: %v | Output: %s", err, string(output))
			continue
		}
		processScanResult(string(output))
	}
}

func processScanResult(output string) {
	lines := strings.Split(output, "\n")
	var tempFoundList []ScannedDevice
	var wg sync.WaitGroup
	var listMutex sync.Mutex

	for _, line := range lines {
		parts := strings.Fields(line)
		// Basic validation for ARP scan output format
		if len(parts) < 2 {
			continue
		}
		ip := parts[0]
		mac := normalizeMAC(parts[1])
		vendor := "Unknown"
		if len(parts) > 2 {
			vendor = strings.Join(parts[2:], " ")
		}

		if strings.Contains(mac, ":") {
			wg.Add(1)
			go func(ip, mac, vendor string) {
				defer wg.Done()
				// Resolve hostname in parallel to speed up the scan cycle
				hostname := lookupHostname(ip)
				if hostname == "" {
					hostname = vendor
				}
				listMutex.Lock()
				tempFoundList = append(tempFoundList, ScannedDevice{IP: ip, MAC: mac, Vendor: vendor, Hostname: hostname})
				listMutex.Unlock()
			}(ip, mac, vendor)
		}
	}
	wg.Wait()

	mutex.Lock()
	defer mutex.Unlock()

	now := time.Now()
	changed := false
	lastScanDevices = tempFoundList
	unknownHistoryChanged := false

	// Reconcile scanned devices with registered users
	for _, dev := range tempFoundList {
		isRegistered := false
		for i := range users {
			if users[i].MAC == dev.MAC {
				isRegistered = true
				users[i].LastSeen = now

				// Update dynamic fields
				if users[i].IP != dev.IP {
					users[i].IP = dev.IP
					changed = true
				}

				// Update hostname if the device exposes a better name than the vendor
				if dev.Hostname != "" && dev.Hostname != dev.Vendor {
					if users[i].Hostname == "" || users[i].Hostname == users[i].Vendor {
						users[i].Hostname = dev.Hostname
						changed = true
					}
				}

				if users[i].Status == "OFFLINE" || users[i].Status == "" {
					users[i].Status = "ONLINE"
					changed = true

					// Avoid notification spam if the device reconnected quickly (flapping)
					if wasFalseAlarm(dev.MAC) {
						log.Printf("Snooze: %s returned within the window.", users[i].Name)
					} else {
						addLogInternal(dev.MAC, users[i].Name, "CONNECTED", "IP: "+dev.IP)
						if users[i].Notify {
							name := users[i].Name
							host := dev.Hostname
							safeName := html.EscapeString(name)
							safeHost := html.EscapeString(host)
							go func(n, h string) {
								err := sendTelegram(fmt.Sprintf("🏠 <b>%s</b> Connected/Online.\n(%s)", n, h))
								if err != nil {
									log.Printf("Failed to send connected notification: %v", err)
								}
							}(safeName, safeHost)
						}
					}
				}
				break
			}
		}

		if !isRegistered {
			// Track history of unknown devices for the "Unknowns" dashboard
			if record, exists := unknownHistory[dev.MAC]; exists {
				record.LastSeen = now
				record.Count++
				record.IP = dev.IP
				if dev.Hostname != "" && dev.Hostname != dev.Vendor {
					record.Hostname = dev.Hostname
				}
				unknownHistory[dev.MAC] = record
			} else {
				unknownHistory[dev.MAC] = UnknownDevice{
					MAC: dev.MAC, IP: dev.IP, Vendor: dev.Vendor, Hostname: dev.Hostname,
					FirstSeen: now, LastSeen: now, Count: 1,
				}
			}
			unknownHistoryChanged = true
		}
	}

	if changed {
		if err := saveUsers(); err != nil {
			log.Printf("Error saving users: %v", err)
		}
	}
	if unknownHistoryChanged {
		saveUnknownHistory()
	}
}

func startTimeoutChecker() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		mutex.Lock()
		now := time.Now()
		changed := false
		for i := range users {
			if users[i].Status == "ONLINE" {
				if now.Sub(users[i].LastSeen) > OfflineTimeout {
					users[i].Status = "OFFLINE"
					changed = true
					addLogInternal(users[i].MAC, users[i].Name, "DISCONNECTED", "Timeout")
					if users[i].Notify {
						name := users[i].Name
						safeName := html.EscapeString(name)
						go func(n string) {
							err := sendTelegram(fmt.Sprintf("👋 <b>%s</b> Disconnected/Offline.", n))
							if err != nil {
								log.Printf("Failed to send disconnected notification: %v", err)
							}
						}(safeName)
					}
				}
			}
		}
		if changed {
			if err := saveUsers(); err != nil {
				log.Printf("Error saving users: %v", err)
			}
		}
		mutex.Unlock()
	}
}

// --- INTERNAL HELPERS ---

// Checks if a disconnect event happened recently; if so, removes the disconnect log to simulate a continuous session
func wasFalseAlarm(mac string) bool {
	for i := len(activityLogs) - 1; i >= 0; i-- {
		if activityLogs[i].MAC == mac {
			if activityLogs[i].Action == "DISCONNECTED" && time.Since(activityLogs[i].Timestamp) < SnoozeWindow {
				activityLogs = append(activityLogs[:i], activityLogs[i+1:]...)
				saveLogs()
				return true
			}
			return false
		}
	}
	return false
}

func addLogInternal(mac, name, action, detail string) {
	entry := LogEntry{ID: time.Now().UnixNano(), Timestamp: time.Now(), MAC: mac, Name: name, Action: action, Detail: detail}
	activityLogs = append(activityLogs, entry)
	// Rotate logs to prevent unbounded growth
	if len(activityLogs) > 1000 {
		activityLogs = activityLogs[len(activityLogs)-1000:]
	}
	saveLogs()
}

func lookupHostname(ip string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2000*time.Millisecond)
	defer cancel()
	// Force using the specific router DNS (usually the gateway) to get local LAN hostnames
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 1000 * time.Millisecond}
			return d.DialContext(ctx, "udp", RouterDNS+":53")
		},
	}
	names, err := resolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	name := strings.TrimSuffix(names[0], ".")
	// Strip common ISP/Router suffixes to keep names clean
	suffixes := []string{".lan", ".local", ".home", ".arpa", ".indihome.net", ".biznet"}
	for _, s := range suffixes {
		if strings.HasSuffix(name, s) {
			name = strings.TrimSuffix(name, s)
			break
		}
	}
	if name == ip {
		return ""
	}
	return name
}

func sendTelegram(msg string) error {
	if TelegramToken == "" || TelegramChat == "" {
		return fmt.Errorf("token/chat_id not configured")
	}
	if msg == "" {
		return fmt.Errorf("message is empty")
	}

	client := &http.Client{Timeout: 10 * time.Second}
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", TelegramToken)
	data := url.Values{}
	data.Set("chat_id", TelegramChat)
	data.Set("text", msg)
	data.Set("parse_mode", "HTML")

	resp, err := client.PostForm(apiURL, data)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("Telegram API Error (%d): %s", resp.StatusCode, string(body))
	}
	return nil
}

// --- FILE I/O ---
// Note: JSON I/O functions assume the caller handles thread-safety (Locks)
func loadUsers() error {
	b, err := ioutil.ReadFile(DataFile)
	if err != nil {
		if os.IsNotExist(err) {
			users = []User{}
			return nil
		}
		return err
	}
	return json.Unmarshal(b, &users)
}
func saveUsers() error {
	b, err := json.MarshalIndent(users, "", " ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(DataFile, b, 0644)
}
func loadLogs() error {
	b, err := ioutil.ReadFile(LogFile)
	if err != nil {
		if os.IsNotExist(err) {
			activityLogs = []LogEntry{}
			return nil
		}
		return err
	}
	return json.Unmarshal(b, &activityLogs)
}
func saveLogs() error {
	b, err := json.MarshalIndent(activityLogs, "", " ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(LogFile, b, 0644)
}
func loadUnknownHistory() error {
	b, err := ioutil.ReadFile(UnknownFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return json.Unmarshal(b, &unknownHistory)
}
func saveUnknownHistory() {
	b, err := json.MarshalIndent(unknownHistory, "", " ")
	if err != nil {
		log.Printf("Error save unknown: %v", err)
		return
	}
	ioutil.WriteFile(UnknownFile, b, 0644)
}
