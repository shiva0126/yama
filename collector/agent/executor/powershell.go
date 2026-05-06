package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
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

// RunPowerShell executes a .ps1 module and returns parsed JSON output
func (e *Executor) RunPowerShell(scriptName, domain string, extraArgs ...string) (map[string]interface{}, error) {
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
	)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "powershell.exe", args...)
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
