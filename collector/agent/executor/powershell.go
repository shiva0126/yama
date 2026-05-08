package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"go.uber.org/zap"
)

type Executor struct {
	psDir  string
	csDir  string
	logger *zap.Logger
}

func New(psDir, csDir string, logger *zap.Logger) *Executor {
	return &Executor{psDir: psDir, csDir: csDir, logger: logger}
}

// psExecutable returns the PowerShell binary name for the current OS.
// On Windows: powershell.exe. On Linux/Mac: pwsh (PowerShell Core).
func psExecutable() (string, error) {
	if runtime.GOOS == "windows" {
		return "powershell.exe", nil
	}
	if path, err := exec.LookPath("pwsh"); err == nil {
		return path, nil
	}
	return "", fmt.Errorf("PowerShell not found: install PowerShell Core (pwsh) on this host")
}

// RunPowerShell executes a .ps1 module and returns parsed JSON output
func (e *Executor) RunPowerShell(scriptName, domain string, extraArgs ...string) (map[string]interface{}, error) {
	psExe, err := psExecutable()
	if err != nil {
		return map[string]interface{}{
			"error":  err.Error(),
			"note":   "PowerShell collection unavailable on this host. LDAP-based scan is used instead.",
			"domain": domain,
		}, nil
	}

	scriptPath := filepath.Join(e.psDir, scriptName)

	args := []string{
		"-NonInteractive",
		"-NoProfile",
		"-ExecutionPolicy", "Bypass",
		"-File", scriptPath,
		"-Domain", domain,
	}
	args = append(args, extraArgs...)

	e.logger.Info("running PowerShell script",
		zap.String("script", scriptName),
		zap.String("domain", domain),
		zap.String("executable", psExe),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, psExe, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	if err := cmd.Run(); err != nil {
		e.logger.Error("PowerShell script failed",
			zap.String("script", scriptName),
			zap.String("stderr", stderr.String()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("script %s failed: %w\nstderr: %s", scriptName, err, stderr.String())
	}

	e.logger.Info("PowerShell script completed",
		zap.String("script", scriptName),
		zap.Duration("duration", time.Since(start)),
	)

	// Parse JSON output
	var result map[string]interface{}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		return nil, fmt.Errorf("failed to parse script output: %w\noutput: %s", err, stdout.String())
	}

	// Check for script-level error
	if errVal, ok := result["error"]; ok && errVal != nil {
		return result, fmt.Errorf("script reported error: %v", errVal)
	}

	return result, nil
}

// ExecuteDefenseAction executes a defensive response action on the local host.
func (e *Executor) ExecuteDefenseAction(command, target string) (map[string]interface{}, error) {
	switch command {
	case "disable-account":
		return e.disableAccount(target)
	default:
		return nil, fmt.Errorf("unsupported defense command: %s", command)
	}
}

func (e *Executor) disableAccount(target string) (map[string]interface{}, error) {
	if strings.TrimSpace(target) == "" {
		return nil, fmt.Errorf("target is required")
	}

	psExe, err := psExecutable()
	if err != nil {
		// In non-AD demo environments (for example Linux dev containers), accept the
		// action so the pipeline remains testable even when host-side execution is unavailable.
		return map[string]interface{}{
			"status":  "accepted-no-executor",
			"command": "disable-account",
			"target":  target,
			"note":    err.Error(),
		}, nil
	}

	escapedTarget := strings.ReplaceAll(target, "'", "''")
	psScript := fmt.Sprintf(
		`$ErrorActionPreference='Stop'; Disable-ADAccount -Identity '%s' -Confirm:$false; @{status='ok'; command='disable-account'; target='%s'} | ConvertTo-Json -Compress`,
		escapedTarget, escapedTarget,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, psExe, "-NonInteractive", "-NoProfile", "-Command", psScript)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("disable-account failed: %w; stderr: %s", err, strings.TrimSpace(stderr.String()))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		return map[string]interface{}{
			"status":  "ok",
			"command": "disable-account",
			"target":  target,
			"output":  strings.TrimSpace(stdout.String()),
		}, nil
	}

	return result, nil
}

// RunDotNetTool executes a compiled C# tool and returns JSON
func (e *Executor) RunDotNetTool(toolName string, args ...string) (map[string]interface{}, error) {
	toolPath := filepath.Join(e.csDir, toolName)

	e.logger.Info("running .NET tool", zap.String("tool", toolName))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, toolPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("tool %s failed: %w\nstderr: %s", toolName, err, stderr.String())
	}

	var result map[string]interface{}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		return nil, fmt.Errorf("failed to parse tool output: %w", err)
	}
	return result, nil
}

// ModuleMap maps task types to their PowerShell script files
var ModuleMap = map[string]string{
	"topology":  "Get-ADTopology.ps1",
	"users":     "Get-ADUsers.ps1",
	"groups":    "Get-ADGroups.ps1",
	"computers": "Get-ADComputers.ps1",
	"gpos":      "Get-ADGPOs.ps1",
	"kerberos":  "Get-KerberosConfig.ps1",
	"acls":      "Get-ACLAnalysis.ps1",
	"dcinfo":    "Get-DCInfo.ps1",
	"trusts":    "Get-TrustInfo.ps1",
	"ous":       "Get-ADOUs.ps1",
	"fgpp":      "Get-FineGrainedPwdPolicy.ps1",
}
