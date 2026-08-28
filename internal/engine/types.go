package engine

import "time"

type Config struct {
	Roots                []string
	AllowExec            bool
	AllowScreen          bool
	AllowComputerControl bool
	StateDir             string
	MaxReadBytes         int
	MaxTaskLogBytes      int64
}

type StartTaskInput struct {
	Command string            `json:"command" jsonschema:"shell command to run in a PTY"`
	Cwd     string            `json:"cwd,omitempty" jsonschema:"working directory; must be inside an allowed root"`
	Name    string            `json:"name,omitempty" jsonschema:"human readable task name"`
	Env     map[string]string `json:"env,omitempty" jsonschema:"additional environment variables"`
}

type ReadTaskInput struct {
	TaskID string `json:"task_id" jsonschema:"task id returned by task_start"`
	Offset int64  `json:"offset,omitempty" jsonschema:"byte offset in the persistent task log"`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum bytes to return"`
}

type WaitTaskInput struct {
	TaskID    string `json:"task_id" jsonschema:"task id returned by task_start"`
	Offset    int64  `json:"offset,omitempty" jsonschema:"byte offset in the persistent task log"`
	Limit     int    `json:"limit,omitempty" jsonschema:"maximum bytes to return"`
	TimeoutMS int    `json:"timeout_ms,omitempty" jsonschema:"long-poll timeout; defaults to 15000 and max 30000"`
}

type SendTaskInput struct {
	TaskID string `json:"task_id"`
	Input  string `json:"input" jsonschema:"bytes/text to write to the task PTY"`
}

type StopTaskInput struct {
	TaskID string `json:"task_id"`
	Signal string `json:"signal,omitempty" jsonschema:"TERM, INT, HUP, or KILL; defaults to TERM"`
}

type FileReadInput struct {
	Path   string `json:"path"`
	Offset int64  `json:"offset,omitempty" jsonschema:"byte offset"`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum bytes to return"`
}

type FileWriteInput struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Mode    string `json:"mode,omitempty" jsonschema:"rewrite or append"`
}

type FileListInput struct {
	Path  string `json:"path"`
	Depth int    `json:"depth,omitempty" jsonschema:"maximum recursion depth, default 1"`
}

type FileSearchInput struct {
	Path       string `json:"path"`
	Pattern    string `json:"pattern" jsonschema:"regular expression"`
	Kind       string `json:"kind,omitempty" jsonschema:"files or content"`
	MaxResults int    `json:"max_results,omitempty"`
}

type CheckpointWriteInput struct {
	Workspace string `json:"workspace" jsonschema:"workspace directory"`
	Content   string `json:"content" jsonschema:"durable context for the next agent turn/session"`
}

type CheckpointReadInput struct {
	Workspace string `json:"workspace"`
}

type TaskInfo struct {
	ID           string     `json:"id"`
	Name         string     `json:"name,omitempty"`
	Command      string     `json:"command"`
	Cwd          string     `json:"cwd"`
	PID          int        `json:"pid"`
	State        string     `json:"state"`
	ExitCode     *int       `json:"exit_code,omitempty"`
	StartedAt    time.Time  `json:"started_at"`
	EndedAt      *time.Time `json:"ended_at,omitempty"`
	LogTruncated bool       `json:"log_truncated,omitempty"`
}

type ReadTaskOutput struct {
	Task       TaskInfo `json:"task"`
	Output     string   `json:"output"`
	NextOffset int64    `json:"next_offset"`
	EOF        bool     `json:"eof"`
}

type FileReadOutput struct {
	Path       string `json:"path"`
	Content    string `json:"content"`
	NextOffset int64  `json:"next_offset"`
	EOF        bool   `json:"eof"`
}

type FileEntry struct {
	Path string `json:"path"`
	Type string `json:"type"`
	Size int64  `json:"size,omitempty"`
}

type FileSearchHit struct {
	Path string `json:"path"`
	Line int    `json:"line,omitempty"`
	Text string `json:"text,omitempty"`
}

type SystemInfoOutput struct {
	Hostname             string   `json:"hostname"`
	OS                   string   `json:"os"`
	Arch                 string   `json:"arch"`
	PID                  int      `json:"pid"`
	Roots                []string `json:"roots"`
	AllowExec            bool     `json:"allow_exec"`
	AllowScreen          bool     `json:"allow_screen"`
	AllowComputerControl bool     `json:"allow_computer_control"`
}

type TaskListOutput struct {
	Tasks []TaskInfo `json:"tasks"`
}

type FileListOutput struct {
	Entries []FileEntry `json:"entries"`
}

type FileSearchOutput struct {
	Hits      []FileSearchHit `json:"hits"`
	Truncated bool            `json:"truncated"`
}

type Ack struct {
	OK bool `json:"ok"`
}

type CheckpointOutput struct {
	Workspace string `json:"workspace"`
	Content   string `json:"content"`
}

type FilePatchInput struct {
	Path     string `json:"path"`
	OldText  string `json:"old_text" jsonschema:"exact text that must already exist"`
	NewText  string `json:"new_text" jsonschema:"replacement text"`
	Expected int    `json:"expected,omitempty" jsonschema:"required match count; defaults to 1"`
}

type FilePatchOutput struct {
	Path         string `json:"path"`
	Replacements int    `json:"replacements"`
}

type ComputerInfoOutput struct {
	ScreenAllowed     bool   `json:"screen_allowed"`
	ControlAllowed    bool   `json:"control_allowed"`
	SessionType       string `json:"session_type,omitempty"`
	Desktop           string `json:"desktop,omitempty"`
	ScreenshotBackend string `json:"screenshot_backend,omitempty"`
	InputBackend      string `json:"input_backend,omitempty"`
}

type ComputerScreenshotInput struct {
	Format      string `json:"format,omitempty" jsonschema:"png or jpeg; defaults to png"`
	JPEGQuality int    `json:"jpeg_quality,omitempty" jsonschema:"1-100; defaults to 85"`
}

type ComputerScreenshotOutput struct {
	MIMEType string `json:"mime_type"`
	Data     []byte `json:"data"`
	Width    int    `json:"width"`
	Height   int    `json:"height"`
}

type ComputerScreenshotMetaOutput struct {
	MIMEType string `json:"mime_type"`
	Width    int    `json:"width"`
	Height   int    `json:"height"`
}

type ComputerMoveInput struct {
	X int `json:"x"`
	Y int `json:"y"`
}
type ComputerClickInput struct {
	Button string `json:"button,omitempty"`
	Clicks int    `json:"clicks,omitempty"`
}
type ComputerScrollInput struct {
	DX int `json:"dx,omitempty"`
	DY int `json:"dy,omitempty"`
}
type ComputerTypeInput struct {
	Text    string `json:"text"`
	DelayMS int    `json:"delay_ms,omitempty"`
}
type ComputerKeyInput struct {
	Keys string `json:"keys" jsonschema:"key chord such as ctrl+shift+p or Return"`
}
