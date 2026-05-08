package orchestrator

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

type InstallStatus string

const (
	InstallPending   InstallStatus = "pending"
	InstallRunning   InstallStatus = "running"
	InstallCompleted InstallStatus = "completed"
	InstallFailed    InstallStatus = "failed"
)

type InstallJob struct {
	ID        string        `json:"id"`
	TargetIP  string        `json:"target_ip"`
	AgentName string        `json:"agent_name"`
	Status    InstallStatus `json:"status"`
	Progress  int           `json:"progress"`
	Message   string        `json:"message"`
	AgentID   string        `json:"agent_id,omitempty"`
	Error     string        `json:"error,omitempty"`
	CreatedAt time.Time     `json:"created_at"`
}

type InstallRequest struct {
	TargetIP  string `json:"target_ip"  binding:"required"`
	Username  string `json:"username"   binding:"required"`
	Password  string `json:"password"   binding:"required"`
	Domain    string `json:"domain"     binding:"required"`
	AgentName string `json:"agent_name" binding:"required"`
	SSHPort   int    `json:"ssh_port"`
	AgentPort int    `json:"agent_port"`
}

type BulkInstallDCsRequest struct {
	SnapshotID      string `json:"snapshot_id" binding:"required"`
	Username        string `json:"username" binding:"required"`
	Password        string `json:"password" binding:"required"`
	Domain          string `json:"domain" binding:"required"`
	AgentNamePrefix string `json:"agent_name_prefix"`
	SSHPort         int    `json:"ssh_port"`
	AgentPort       int    `json:"agent_port"`
}

var installJobs sync.Map // jobID -> *InstallJob

func (o *Orchestrator) InstallAgent(c *gin.Context) {
	var req InstallRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.SSHPort == 0 {
		req.SSHPort = 22
	}
	if req.AgentPort == 0 {
		req.AgentPort = 9090
	}

	job := &InstallJob{
		ID:        uuid.New().String(),
		TargetIP:  req.TargetIP,
		AgentName: req.AgentName,
		Status:    InstallPending,
		Progress:  0,
		Message:   "Installation queued",
		CreatedAt: time.Now(),
	}
	installJobs.Store(job.ID, job)

	go o.runInstall(job, req)

	c.JSON(http.StatusAccepted, gin.H{"job_id": job.ID, "message": "Installation started"})
}

func (o *Orchestrator) GetInstallStatus(c *gin.Context) {
	jobID := c.Param("jobId")
	val, ok := installJobs.Load(jobID)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "install job not found"})
		return
	}
	c.JSON(http.StatusOK, val.(*InstallJob))
}

func (o *Orchestrator) ListInstallJobs(c *gin.Context) {
	var jobs []*InstallJob
	installJobs.Range(func(_, v any) bool {
		jobs = append(jobs, v.(*InstallJob))
		return true
	})
	c.JSON(http.StatusOK, gin.H{"jobs": jobs})
}

// InstallAgentsForDomainControllers queues installer jobs for all DCs in a snapshot.
func (o *Orchestrator) InstallAgentsForDomainControllers(c *gin.Context) {
	var req BulkInstallDCsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.SSHPort == 0 {
		req.SSHPort = 22
	}
	if req.AgentPort == 0 {
		req.AgentPort = 9090
	}
	if strings.TrimSpace(req.AgentNamePrefix) == "" {
		req.AgentNamePrefix = "DC-Agent"
	}

	dcs, err := o.fetchSnapshotDCs(req.SnapshotID)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	if len(dcs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no domain controllers found in selected snapshot"})
		return
	}

	queued := make([]map[string]string, 0, len(dcs))
	skipped := make([]map[string]string, 0)
	for i, dc := range dcs {
		targetIP := strings.TrimSpace(dc.IP)
		if targetIP == "" {
			resolvedIP, resolveErr := resolveToIPv4(dc.Host)
			if resolveErr != nil || resolvedIP == "" {
				skipped = append(skipped, map[string]string{
					"dc":     dc.Name,
					"reason": "unable to resolve host to IPv4",
				})
				continue
			}
			targetIP = resolvedIP
		}

		var exists int
		_ = o.db.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM agents WHERE ip_address=$1`, targetIP,
		).Scan(&exists)
		if exists > 0 {
			skipped = append(skipped, map[string]string{
				"dc":     dc.Name,
				"reason": "agent already exists for this IP",
			})
			continue
		}

		agentName := fmt.Sprintf("%s-%02d", req.AgentNamePrefix, i+1)
		installReq := InstallRequest{
			TargetIP:  targetIP,
			Username:  req.Username,
			Password:  req.Password,
			Domain:    req.Domain,
			AgentName: agentName,
			SSHPort:   req.SSHPort,
			AgentPort: req.AgentPort,
		}

		job := &InstallJob{
			ID:        uuid.New().String(),
			TargetIP:  targetIP,
			AgentName: agentName,
			Status:    InstallPending,
			Progress:  0,
			Message:   "Bulk DC installation queued",
			CreatedAt: time.Now(),
		}
		installJobs.Store(job.ID, job)
		go o.runInstall(job, installReq)

		queued = append(queued, map[string]string{
			"job_id":      job.ID,
			"dc":          dc.Name,
			"host":        dc.Host,
			"target_ip":   targetIP,
			"agent_name":  agentName,
		})
	}

	c.JSON(http.StatusAccepted, gin.H{
		"snapshot_id": req.SnapshotID,
		"queued":      queued,
		"skipped":     skipped,
		"queued_count": len(queued),
		"dc_count":    len(dcs),
	})
}

// ServeAgentBinary serves the compiled Windows agent executable.
func (o *Orchestrator) ServeAgentBinary(c *gin.Context) {
	binaryPath := agentBinaryPath()
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "agent binary not found — run 'make build-agent' first",
		})
		return
	}
	c.Header("Content-Disposition", "attachment; filename=yama-agent.exe")
	c.File(binaryPath)
}

func agentBinaryPath() string {
	if p := os.Getenv("AGENT_BINARY_PATH"); p != "" {
		return p
	}
	for _, p := range []string{"./yama-agent.exe", "/app/yama-agent.exe"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "./yama-agent.exe"
}

type snapshotDC struct {
	Name string
	Host string
	IP   string
}

func (o *Orchestrator) fetchSnapshotDCs(snapshotID string) ([]snapshotDC, error) {
	url := strings.TrimRight(o.cfg.InventoryServiceURL, "/") + "/snapshots/" + snapshotID + "/dcs"
	resp, err := o.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch dcs from inventory-service: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("inventory-service returned status %d while loading dcs", resp.StatusCode)
	}

	var payload struct {
		Items []map[string]interface{} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode dcs payload: %w", err)
	}

	dcs := make([]snapshotDC, 0, len(payload.Items))
	for _, item := range payload.Items {
		name := str(item, "name")
		host := str(item, "host_name")
		ip := str(item, "ip_address")
		if host == "" {
			host = name
		}
		if host == "" && ip == "" {
			continue
		}
		dcs = append(dcs, snapshotDC{Name: name, Host: host, IP: ip})
	}
	return dcs, nil
}

func resolveToIPv4(host string) (string, error) {
	if net.ParseIP(host) != nil {
		return host, nil
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return "", err
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4.String(), nil
		}
	}
	if len(ips) > 0 {
		return ips[0].String(), nil
	}
	return "", fmt.Errorf("no ip found")
}

func str(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}

func (o *Orchestrator) runInstall(job *InstallJob, req InstallRequest) {
	update := func(progress int, message string, status InstallStatus) {
		job.Progress = progress
		job.Message = message
		job.Status = status
		payload, _ := json.Marshal(map[string]interface{}{
			"job_id":   job.ID,
			"progress": progress,
			"message":  message,
			"status":   string(status),
		})
		o.rdb.Publish(context.Background(), "agent:install", string(payload))
	}

	update(5, "Locating agent binary...", InstallRunning)

	binaryData, err := os.ReadFile(agentBinaryPath())
	if err != nil {
		job.Error = "Agent binary not found. Run 'make build-agent' first."
		update(0, job.Error, InstallFailed)
		return
	}

	update(10, "Connecting via SSH...", InstallRunning)

	sshCfg := &ssh.ClientConfig{
		User:            req.Username,
		Auth:            []ssh.AuthMethod{ssh.Password(req.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // acceptable for internal LAN use
		Timeout:         30 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", req.TargetIP, req.SSHPort)
	client, err := ssh.Dial("tcp", addr, sshCfg)
	if err != nil {
		job.Error = fmt.Sprintf("SSH connection failed: %v", err)
		update(0, job.Error, InstallFailed)
		return
	}
	defer client.Close()

	update(20, "Connected. Creating installation directory...", InstallRunning)

	if err := sshRun(client, `powershell -NonInteractive -Command "New-Item -ItemType Directory -Force -Path 'C:\yama' | Out-Null"`); err != nil {
		job.Error = fmt.Sprintf("Failed to create directory: %v", err)
		update(0, job.Error, InstallFailed)
		return
	}

	update(35, "Uploading agent binary (this may take a moment)...", InstallRunning)

	if err := sshUpload(client, binaryData, `C:\yama\yama-agent.exe`); err != nil {
		job.Error = fmt.Sprintf("Failed to upload binary: %v", err)
		update(0, job.Error, InstallFailed)
		return
	}

	update(65, "Removing any previous service installation...", InstallRunning)

	// Clean up old service gracefully
	sshRun(client, `powershell -NonInteractive -Command "Stop-Service -Name 'YamaAgent' -Force -ErrorAction SilentlyContinue"`)
	sshRun(client, `powershell -NonInteractive -Command "& sc.exe delete YamaAgent" `)
	time.Sleep(2 * time.Second)

	update(70, "Installing Windows service...", InstallRunning)

	installAPIKey := generateAPIKey()
	installAgentID := uuid.New().String()
	installCmd := fmt.Sprintf(
		`powershell -NonInteractive -Command "New-Service -Name 'YamaAgent' -BinaryPathName 'C:\yama\yama-agent.exe --port %d --api-key %s' -DisplayName 'Yama AD Collector Agent' -StartupType Automatic -Description 'Yama Active Directory Assessment Collector' -ErrorAction Stop"`,
		req.AgentPort, installAPIKey,
	)
	if err := sshRun(client, installCmd); err != nil {
		job.Error = fmt.Sprintf("Failed to install service: %v", err)
		update(0, job.Error, InstallFailed)
		return
	}

	update(80, "Starting service...", InstallRunning)

	if err := sshRun(client, `powershell -NonInteractive -Command "Start-Service -Name 'YamaAgent' -ErrorAction Stop"`); err != nil {
		job.Error = fmt.Sprintf("Failed to start service: %v", err)
		update(0, job.Error, InstallFailed)
		return
	}

	update(88, "Waiting for agent to come online...", InstallRunning)

	agentURL := fmt.Sprintf("http://%s:%d/health", req.TargetIP, req.AgentPort)
	online := false
	httpCli := &http.Client{Timeout: 5 * time.Second}
	for i := 0; i < 12; i++ {
		time.Sleep(5 * time.Second)
		resp, err := httpCli.Get(agentURL)
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			online = true
			break
		}
		o.logger.Debug("waiting for agent", zap.String("url", agentURL), zap.Int("attempt", i+1))
	}

	if !online {
		job.Error = fmt.Sprintf(
			"Agent installed but did not respond on port %d within 60s. "+
				"Check Windows Firewall rules for TCP %d.", req.AgentPort, req.AgentPort,
		)
		update(88, job.Error, InstallFailed)
		return
	}

	update(95, "Registering agent in Yama...", InstallRunning)

	hostname := req.TargetIP
	if names, err := net.LookupAddr(req.TargetIP); err == nil && len(names) > 0 {
		hostname = strings.TrimSuffix(names[0], ".")
	}

	_, err = o.db.Exec(context.Background(),
		`INSERT INTO agents (id, name, hostname, domain, ip_address, api_key, status, last_seen, version, capabilities)
		 VALUES ($1, $2, $3, $4, $5, $6, 'online', NOW(), '1.0.0', $7)`,
		installAgentID, req.AgentName, hostname, req.Domain, req.TargetIP, installAPIKey,
		[]string{
			"topology", "users", "groups", "computers", "gpos", "kerberos", "acls", "dcinfo",
			"trusts", "ous", "fgpp", "adcs", "sites", "service-identities", "ad-vuln-scan",
			"defense:signal-forward", "defense:status", "defense:execute",
		},
	)
	if err != nil {
		job.Error = fmt.Sprintf("Agent installed but DB registration failed: %v", err)
		update(95, job.Error, InstallFailed)
		return
	}

	job.AgentID = installAgentID
	update(100, "Agent installed and registered successfully!", InstallCompleted)
	o.logger.Info("agent installed via SSH", zap.String("agent_id", installAgentID), zap.String("target", req.TargetIP))
}

// sshRun opens a new session on client and runs cmd.
func sshRun(client *ssh.Client, cmd string) error {
	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	return sess.Run(cmd)
}

// sshUpload encodes data as base64 and pipes it via stdin to PowerShell, which
// writes the decoded binary to remotePath.
func sshUpload(client *ssh.Client, data []byte, remotePath string) error {
	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()

	encoded := base64.StdEncoding.EncodeToString(data)
	sess.Stdin = strings.NewReader(encoded)

	cmd := fmt.Sprintf(
		`powershell -NonInteractive -Command `+
			`"$b64 = [Console]::In.ReadToEnd().Trim(); `+
			`[IO.File]::WriteAllBytes('%s', [Convert]::FromBase64String($b64))"`,
		remotePath,
	)
	return sess.Run(cmd)
}
