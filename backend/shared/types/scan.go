package types

import "time"

type ScanStatus string

const (
	ScanStatusPending    ScanStatus = "pending"
	ScanStatusRunning    ScanStatus = "running"
	ScanStatusCompleted  ScanStatus = "completed"
	ScanStatusFailed     ScanStatus = "failed"
	ScanStatusCancelled  ScanStatus = "cancelled"
)

type TaskType string

const (
	TaskTypeTopology  TaskType = "topology"
	TaskTypeUsers     TaskType = "users"
	TaskTypeGroups    TaskType = "groups"
	TaskTypeComputers TaskType = "computers"
	TaskTypeGPOs      TaskType = "gpos"
	TaskTypeKerberos  TaskType = "kerberos"
	TaskTypeACLs      TaskType = "acls"
	TaskTypeDCInfo    TaskType = "dcinfo"
	TaskTypeTrusts    TaskType = "trusts"
	TaskTypeOUs       TaskType = "ous"
	TaskTypeFGPP      TaskType = "fgpp"
	TaskTypeADCS      TaskType = "adcs"
	TaskTypeSites     TaskType = "sites"
)

var AllTaskTypes = []TaskType{
	TaskTypeTopology,
	TaskTypeUsers,
	TaskTypeGroups,
	TaskTypeComputers,
	TaskTypeGPOs,
	TaskTypeKerberos,
	TaskTypeACLs,
	TaskTypeDCInfo,
	TaskTypeTrusts,
	TaskTypeOUs,
	TaskTypeFGPP,
	TaskTypeADCS,
	TaskTypeSites,
}

type ScanJob struct {
	ID          string     `json:"id"`
	AgentID     string     `json:"agent_id"`
	Domain      string     `json:"domain"`
	Status      ScanStatus `json:"status"`
	Progress    int        `json:"progress"` // 0-100
	CreatedAt   time.Time  `json:"created_at"`
	StartedAt   *time.Time `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at"`
	Tasks       []ScanTask `json:"tasks"`
	Error       string     `json:"error,omitempty"`
	SnapshotID  string     `json:"snapshot_id,omitempty"`
	ScoreCard   *ScoreCard `json:"score_card,omitempty"`
}

type ScanTask struct {
	ID          string     `json:"id"`
	ScanID      string     `json:"scan_id"`
	Type        TaskType   `json:"type"`
	Status      ScanStatus `json:"status"`
	StartedAt   *time.Time `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at"`
	Error       string     `json:"error,omitempty"`
	ItemsFound  int        `json:"items_found"`
}

type ScoreCard struct {
	OverallScore    int            `json:"overall_score"`    // 0-100 (higher = better)
	CategoryScores  map[string]int `json:"category_scores"`
	CriticalCount   int            `json:"critical_count"`
	HighCount       int            `json:"high_count"`
	MediumCount     int            `json:"medium_count"`
	LowCount        int            `json:"low_count"`
	InfoCount       int            `json:"info_count"`
	TotalFindings   int            `json:"total_findings"`
	PassedChecks    int            `json:"passed_checks"`
	TotalChecks     int            `json:"total_checks"`
}

// CollectorAgent represents a registered collector agent
type CollectorAgent struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Hostname    string    `json:"hostname"`
	Domain      string    `json:"domain"`
	IPAddress   string    `json:"ip_address"`
	Port        int       `json:"port"`
	APIKey      string    `json:"api_key,omitempty"`
	Status      string    `json:"status"` // online, offline, busy
	LastSeen    time.Time `json:"last_seen"`
	Version     string    `json:"version"`
	Capabilities []string `json:"capabilities"`
}

// ScanRequest is the payload to start a new scan
type ScanRequest struct {
	AgentID   string     `json:"agent_id" binding:"required"`
	Domain    string     `json:"domain" binding:"required"`
	TaskTypes []TaskType `json:"task_types"` // empty = all tasks
}

// WSMessage is a WebSocket event sent to the frontend
type WSMessage struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload"`
}

const (
	WSTypeScanProgress  = "scan_progress"
	WSTypeScanComplete  = "scan_complete"
	WSTypeScanError     = "scan_error"
	WSTypeAgentStatus   = "agent_status"
	WSTypeNewFinding    = "new_finding"
)

// RedisChannels for pub/sub
const (
	RedisScanProgressChannel = "scan:progress"
	RedisAgentStatusChannel  = "agent:status"
	RedisNewFindingChannel   = "finding:new"
)
