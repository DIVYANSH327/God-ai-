// Package main implements GOD SENTINEL v0.6.0 Go Micro-Agent (SentinelAgent.go).
//
// Architecture & Safety Invariants:
//   - Authorized, least-privilege defensive telemetry agent (zero listening ports, zero remote shell).
//   - Collects system load metrics (1m/5m/15m load average, CPU%, RAM%, Disk%, Uptime).
//   - Enforces outbound HTTPS (TLS 1.2/1.3) with short-lived per-device credentials.
//   - Transmits heartbeats to:
//       1. GOD Sentinel Controller API (/api/sentinel/agent/heartbeat)
//       2. Cloud Firestore REST API (users/{uid}/sentinelHeartbeats/{heartbeatId})
//          synchronized in real time by SentinelProvider's onSnapshot listener.
//   - Buffers failed heartbeats in a bounded offline queue and retries with exponential backoff.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	AgentVersion       = "0.6.0"
	DefaultIntervalSec = 15
	MaxOfflineQueue    = 256
)

// AgentConfig defines runtime identity, transport security, and target endpoints.
// Credentials must be supplied via environment variables or short-lived token files—never hardcoded.
type AgentConfig struct {
	AgentID                 string
	Hostname                string
	Region                  string
	ControllerURL           string
	DeviceBearerToken       string
	FirestoreProjectID      string
	FirestoreDatabaseID     string
	FirestoreOwnerUID       string
	FirestoreShortLivedAuth string
	HeartbeatInterval       time.Duration
	AllowInsecureLocalhost  bool
}

// SystemLoadMetrics captures basic least-privilege server health metrics.
type SystemLoadMetrics struct {
	CPUPercent  int     `json:"cpuPercent"`
	RAMPercent  int     `json:"ramPercent"`
	DiskPercent int     `json:"diskPercent"`
	LoadAvg1    float64 `json:"loadAvg1"`
	LoadAvg5    float64 `json:"loadAvg5"`
	LoadAvg15   float64 `json:"loadAvg15"`
	UptimeSec   int64   `json:"uptimeSec"`
	LatencyMs   int64   `json:"latencyMs"`
}

// HeartbeatPayload matches both /api/sentinel/agent/heartbeat and SentinelProvider's
// SentinelHeartbeat schema in firebase-blueprint.json.
type HeartbeatPayload struct {
	ID           string            `json:"id"`
	AgentID      string            `json:"agentId"`
	UserID       string            `json:"userId,omitempty"`
	Hostname     string            `json:"hostname"`
	Region       string            `json:"region"`
	AgentVersion string            `json:"agentVersion"`
	Health       string            `json:"health"` // "healthy" | "warning" | "critical"
	DataOrigin   string            `json:"dataOrigin"`
	ObservedAt   string            `json:"observedAt"`
	Metrics      SystemLoadMetrics `json:"metrics"`
}

// OfflineRingBuffer retains unsent heartbeats when outbound connectivity drops.
type OfflineRingBuffer struct {
	mu    sync.Mutex
	items []HeartbeatPayload
	limit int
}

func NewOfflineRingBuffer(limit int) *OfflineRingBuffer {
	if limit <= 0 {
		limit = MaxOfflineQueue
	}
	return &OfflineRingBuffer{limit: limit}
}

func (b *OfflineRingBuffer) Enqueue(p HeartbeatPayload) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.items) >= b.limit {
		b.items = b.items[1:]
	}
	b.items = append(b.items, p)
}

func (b *OfflineRingBuffer) Drain() []HeartbeatPayload {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]HeartbeatPayload, len(b.items))
	copy(out, b.items)
	b.items = nil
	return out
}

// SentinelTransmitter manages TLS-hardened outbound delivery to the GOD Controller
// and/or Firestore backend consumed by SentinelProvider.
type SentinelTransmitter struct {
	cfg    AgentConfig
	client *http.Client
	buffer *OfflineRingBuffer
}

func NewSentinelTransmitter(cfg AgentConfig) (*SentinelTransmitter, error) {
	if cfg.ControllerURL != "" {
		if err := validateOutboundHTTPS(cfg.ControllerURL, cfg.AllowInsecureLocalhost); err != nil {
			return nil, err
		}
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		DialContext: (&net.Dialer{
			Timeout:   8 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ResponseHeaderTimeout: 10 * time.Second,
	}
	return &SentinelTransmitter{
		cfg: cfg,
		client: &http.Client{
			Transport: transport,
			Timeout:   15 * time.Second,
		},
		buffer: NewOfflineRingBuffer(MaxOfflineQueue),
	}, nil
}

// validateOutboundHTTPS enforces outbound HTTPS-only transport except explicit localhost dev testing.
func validateOutboundHTTPS(rawURL string, allowLocalhost bool) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid controller URL: %w", err)
	}
	if parsed.Scheme == "https" {
		return nil
	}
	host := strings.ToLower(parsed.Hostname())
	if parsed.Scheme == "http" && allowLocalhost && (host == "127.0.0.1" || host == "localhost" || host == "::1") {
		return nil
	}
	return errors.New("outbound communication must use HTTPS (TLS) for non-localhost endpoints")
}

// CollectSystemLoad gathers CPU, memory, disk, uptime, and load average metrics using read-only OS interfaces.
func CollectSystemLoad() SystemLoadMetrics {
	m := SystemLoadMetrics{
		CPUPercent:  readLinuxCPUPercent(),
		RAMPercent:  readLinuxRAMPercent(),
		DiskPercent: readRootDiskPercent(),
		UptimeSec:   readLinuxUptimeSec(),
	}
	m.LoadAvg1, m.LoadAvg5, m.LoadAvg15 = readLinuxLoadAvg()
	return m
}

func classifyHealth(m SystemLoadMetrics) string {
	if m.CPUPercent >= 88 || m.RAMPercent >= 90 || m.DiskPercent >= 92 || m.LoadAvg1 >= 6.0 {
		return "critical"
	}
	if m.CPUPercent >= 68 || m.RAMPercent >= 75 || m.DiskPercent >= 80 || m.LoadAvg1 >= 2.5 {
		return "warning"
	}
	return "healthy"
}

func readLinuxLoadAvg() (float64, float64, float64) {
	if runtime.GOOS != "linux" {
		return 0, 0, 0
	}
	raw, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0
	}
	fields := strings.Fields(string(raw))
	if len(fields) < 3 {
		return 0, 0, 0
	}
	l1, _ := strconv.ParseFloat(fields[0], 64)
	l5, _ := strconv.ParseFloat(fields[1], 64)
	l15, _ := strconv.ParseFloat(fields[2], 64)
	return l1, l5, l15
}

func readLinuxCPUPercent() int {
	if runtime.GOOS != "linux" {
		return 0
	}
	readSample := func() (uint64, uint64, error) {
		raw, err := os.ReadFile("/proc/stat")
		if err != nil {
			return 0, 0, err
		}
		line := strings.SplitN(string(raw), "\n", 2)[0]
		parts := strings.Fields(line)
		if len(parts) < 5 {
			return 0, 0, errors.New("unexpected /proc/stat format")
		}
		var total, idle uint64
		for i := 1; i < len(parts) && i <= 8; i++ {
			v, _ := strconv.ParseUint(parts[i], 10, 64)
			total += v
			if i == 4 || i == 5 {
				idle += v
			}
		}
		return idle, total, nil
	}
	idle1, total1, err := readSample()
	if err != nil {
		return 0
	}
	time.Sleep(150 * time.Millisecond)
	idle2, total2, err := readSample()
	if err != nil || total2 <= total1 {
		return 0
	}
	pct := int((1.0 - float64(idle2-idle1)/float64(total2-total1)) * 100.0)
	return clampInt(pct, 0, 100)
}

func readLinuxRAMPercent() int {
	if runtime.GOOS != "linux" {
		return 0
	}
	raw, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	var total, avail, free uint64
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		val, _ := strconv.ParseUint(fields[1], 10, 64)
		switch fields[0] {
		case "MemTotal:":
			total = val
		case "MemAvailable:":
			avail = val
		case "MemFree:":
			free = val
		}
	}
	if total == 0 {
		return 0
	}
	if avail == 0 {
		avail = free
	}
	return clampInt(int(float64(total-avail)/float64(total)*100.0), 0, 100)
}

func readRootDiskPercent() int {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil || stat.Blocks == 0 {
		return 0
	}
	used := stat.Blocks - stat.Bfree
	return clampInt(int(float64(used)/float64(stat.Blocks)*100.0), 0, 100)
}

func readLinuxUptimeSec() int64 {
	if runtime.GOOS != "linux" {
		return 0
	}
	raw, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(raw))
	if len(fields) == 0 {
		return 0
	}
	secs, _ := strconv.ParseFloat(fields[0], 64)
	return int64(secs)
}

func clampInt(v, minV, maxV int) int {
	if v < minV {
		return minV
	}
	if v > maxV {
		return maxV
	}
	return v
}

func newHeartbeatID(agentID string) string {
	buf := make([]byte, 6)
	_, _ = rand.Read(buf)
	sum := sha256.Sum256([]byte(agentID + ":" + hex.EncodeToString(buf)))
	return "hb_" + hex.EncodeToString(sum[:])[:14]
}

// TransmitHeartbeatToController delivers an authenticated heartbeat to the GOD Sentinel backend.
func (t *SentinelTransmitter) TransmitHeartbeatToController(ctx context.Context, p HeartbeatPayload) error {
	if t.cfg.ControllerURL == "" || t.cfg.DeviceBearerToken == "" {
		return nil
	}
	endpoint := strings.TrimRight(t.cfg.ControllerURL, "/") + "/api/sentinel/agent/heartbeat"
	wire := map[string]any{
		"agentVersion": p.AgentVersion,
		"cpuPercent":   p.Metrics.CPUPercent,
		"ramPercent":   p.Metrics.RAMPercent,
		"diskPercent":  p.Metrics.DiskPercent,
		"loadAvg1":     p.Metrics.LoadAvg1,
		"uptimeSec":    p.Metrics.UptimeSec,
		"latencyMs":    p.Metrics.LatencyMs,
		"dataOrigin":   p.DataOrigin,
	}
	body, err := json.Marshal(wire)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+t.cfg.DeviceBearerToken)
	req.Header.Set("X-Sentinel-Agent-Id", t.cfg.AgentID)
	req.Header.Set("User-Agent", "GOD-Sentinel-Go/"+AgentVersion)

	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("controller heartbeat rejected (%d): %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}

// TransmitHeartbeatToFirestore writes a validated SentinelHeartbeat document directly to
// Cloud Firestore's REST API under users/{uid}/sentinelHeartbeats/{heartbeatId}.
// SentinelProvider subscribes to this subcollection via onSnapshot to drive the 5-minute pulse chart.
func (t *SentinelTransmitter) TransmitHeartbeatToFirestore(ctx context.Context, p HeartbeatPayload) error {
	if t.cfg.FirestoreProjectID == "" || t.cfg.FirestoreOwnerUID == "" || t.cfg.FirestoreShortLivedAuth == "" {
		return nil
	}
	dbID := t.cfg.FirestoreDatabaseID
	if dbID == "" {
		dbID = "(default)"
	}

	// Uses Firestore REST API v1 with short-lived Firebase ID token so firestore.rules enforces
	// isVerifiedOwner(userId) and isValidSentinelHeartbeat(incoming(), heartbeatId).
	endpoint := fmt.Sprintf(
		"https://firestore.googleapis.com/v1/projects/%s/databases/%s/documents/users/%s/sentinelHeartbeats?documentId=%s",
		url.PathEscape(t.cfg.FirestoreProjectID),
		url.PathEscape(dbID),
		url.PathEscape(t.cfg.FirestoreOwnerUID),
		url.QueryEscape(p.ID),
	)

	fsDoc := map[string]any{
		"fields": map[string]any{
			"id":          map[string]string{"stringValue": p.ID},
			"userId":      map[string]string{"stringValue": t.cfg.FirestoreOwnerUID},
			"agentId":     map[string]string{"stringValue": p.AgentID},
			"hostname":    map[string]string{"stringValue": p.Hostname},
			"region":      map[string]string{"stringValue": p.Region},
			"health":      map[string]string{"stringValue": p.Health},
			"cpuPercent":  map[string]string{"integerValue": strconv.Itoa(p.Metrics.CPUPercent)},
			"ramPercent":  map[string]string{"integerValue": strconv.Itoa(p.Metrics.RAMPercent)},
			"diskPercent": map[string]string{"integerValue": strconv.Itoa(p.Metrics.DiskPercent)},
			"loadAvg1":    map[string]float64{"doubleValue": p.Metrics.LoadAvg1},
			"latencyMs":   map[string]string{"integerValue": strconv.FormatInt(p.Metrics.LatencyMs, 10)},
			"dataOrigin":  map[string]string{"stringValue": p.DataOrigin},
			"observedAt":  map[string]string{"timestampValue": p.ObservedAt},
		},
	}

	body, err := json.Marshal(fsDoc)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+t.cfg.FirestoreShortLivedAuth)
	req.Header.Set("User-Agent", "GOD-Sentinel-Go/"+AgentVersion)

	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("firestore heartbeat write failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}

// SendWithRetry transmits a heartbeat (plus any buffered offline pings) with bounded exponential backoff.
func (t *SentinelTransmitter) SendWithRetry(ctx context.Context, current HeartbeatPayload) error {
	pending := append(t.buffer.Drain(), current)
	var lastErr error

	for idx, item := range pending {
		delivered := false
		for attempt := 0; attempt < 3; attempt++ {
			start := time.Now()
			errCtrl := t.TransmitHeartbeatToController(ctx, item)
			item.Metrics.LatencyMs = time.Since(start).Milliseconds()
			errFS := t.TransmitHeartbeatToFirestore(ctx, item)
			if errCtrl == nil && errFS == nil {
				delivered = true
				break
			}
			lastErr = errors.Join(errCtrl, errFS)
			backoff := time.Duration(400*(1<<attempt)) * time.Millisecond
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
		}
		if !delivered {
			for _, rem := range pending[idx:] {
				t.buffer.Enqueue(rem)
			}
			return lastErr
		}
	}
	return nil
}

func main() {
	controllerURL := flag.String("controller", os.Getenv("GOD_SENTINEL_CONTROLLER_URL"), "GOD Sentinel HTTPS controller base URL")
	agentID := flag.String("agent-id", os.Getenv("GOD_SENTINEL_AGENT_ID"), "Enrolled Sentinel agent ID")
	region := flag.String("region", envOrDefault("GOD_SENTINEL_REGION", "asia-southeast1"), "Server region label")
	intervalSec := flag.Int("interval", DefaultIntervalSec, "Heartbeat interval in seconds")
	once := flag.Bool("once", false, "Collect and transmit one heartbeat then exit")
	allowLocalhost := flag.Bool("allow-insecure-localhost", false, "Allow HTTP only for 127.0.0.1/localhost dev testing")
	flag.Parse()

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "authorized-go-server"
	}

	cfg := AgentConfig{
		AgentID:                 *agentID,
		Hostname:                hostname,
		Region:                  *region,
		ControllerURL:           *controllerURL,
		DeviceBearerToken:       os.Getenv("GOD_SENTINEL_DEVICE_TOKEN"),
		FirestoreProjectID:      os.Getenv("GOD_FIRESTORE_PROJECT_ID"),
		FirestoreDatabaseID:     os.Getenv("GOD_FIRESTORE_DATABASE_ID"),
		FirestoreOwnerUID:       os.Getenv("GOD_FIRESTORE_OWNER_UID"),
		FirestoreShortLivedAuth: os.Getenv("GOD_FIRESTORE_BEARER_TOKEN"),
		HeartbeatInterval:       time.Duration(maxInt(*intervalSec, 5)) * time.Second,
		AllowInsecureLocalhost:  *allowLocalhost,
	}

	if cfg.AgentID == "" {
		fmt.Fprintln(os.Stderr, "error: --agent-id or GOD_SENTINEL_AGENT_ID is required")
		os.Exit(2)
	}

	tx, err := NewSentinelTransmitter(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error initializing transmitter: %v\n", err)
		os.Exit(2)
	}

	runOnce := func() {
		metrics := CollectSystemLoad()
		payload := HeartbeatPayload{
			ID:           newHeartbeatID(cfg.AgentID),
			AgentID:      cfg.AgentID,
			UserID:       cfg.FirestoreOwnerUID,
			Hostname:     cfg.Hostname,
			Region:       cfg.Region,
			AgentVersion: AgentVersion,
			Health:       classifyHealth(metrics),
			DataOrigin:   "real_telemetry",
			ObservedAt:   time.Now().UTC().Format(time.RFC3339Nano),
			Metrics:      metrics,
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		if err := tx.SendWithRetry(ctx, payload); err != nil {
			fmt.Fprintf(os.Stderr, `{"event":"heartbeat_buffered","agentId":%q,"error":%q}`+"\n", cfg.AgentID, err.Error())
			return
		}
		out, _ := json.Marshal(map[string]any{
			"event":      "heartbeat_transmitted",
			"agentId":    payload.AgentID,
			"health":     payload.Health,
			"cpuPercent": payload.Metrics.CPUPercent,
			"ramPercent": payload.Metrics.RAMPercent,
			"loadAvg1":   payload.Metrics.LoadAvg1,
			"observedAt": payload.ObservedAt,
		})
		fmt.Println(string(out))
	}

	runOnce()
	if *once {
		return
	}

	ticker := time.NewTicker(cfg.HeartbeatInterval)
	defer ticker.Stop()
	for range ticker.C {
		runOnce()
	}
}

func envOrDefault(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
