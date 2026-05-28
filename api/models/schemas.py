"""Pydantic request/response modelleri."""
from __future__ import annotations
from typing import Any, Optional
from pydantic import BaseModel, Field


# ── Chat ────────────────────────────────────────────────────────────────────

class ReasoningConfig(BaseModel):
    enabled: bool = True
    effort: str = "medium"  

class ChatRequest(BaseModel):
    message: str = Field(..., description="Kullanıcı mesajı")
    session_id: Optional[str] = None
    system: Optional[str] = None
    history: Optional[list[dict]] = None
    model: Optional[str] = None
    provider: Optional[str] = None
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    max_iterations: int = 90
    max_tokens: Optional[int] = None
    temperature: Optional[float] = None
    top_p: Optional[float] = None
    reasoning: Optional[ReasoningConfig] = None
    thinking_budget: Optional[int] = None
    service_tier: Optional[str] = None
    toolsets: Optional[list[str]] = None
    disabled_tools: Optional[list[str]] = None
    skills: Optional[list[str]] = None
    yolo: bool = False
    fast_mode: bool = False
    stream: bool = False
    file_ids: Optional[list[str]] = None

class ToolCall(BaseModel):
    name: str
    call_id: str
    args: dict = {}
    result: Optional[str] = None

class UsageInfo(BaseModel):
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0

class ChatResponse(BaseModel):
    id: str
    session_id: str
    model: str
    provider: str
    response: str
    tool_calls: list[ToolCall] = []
    tool_call_count: int = 0
    iteration_count: int = 0
    usage: UsageInfo = UsageInfo()
    duration_ms: float = 0
    stopped_by: str = "agent"

class BackgroundTaskResponse(BaseModel):
    task_id: str
    status: str  # queued | running | done | error
    result: Optional[ChatResponse] = None
    progress: Optional[dict] = None
    error: Optional[str] = None

class ChatApproveRequest(BaseModel):
    tool_call_id: str
    approve: bool = True
    reason: Optional[str] = None


# ── Models ───────────────────────────────────────────────────────────────────

class ModelInfo(BaseModel):
    id: str
    provider: str
    display_name: str = ""
    context_length: int = 0
    max_output_tokens: int = 0
    supports_reasoning: bool = False
    supports_vision: bool = False
    supports_tools: bool = True
    pricing: dict = {}
    free: bool = False
    recommended: bool = False

class ModelsListResponse(BaseModel):
    providers: list[str]
    current_model: str
    current_provider: str
    models: list[ModelInfo]

class ModelSwitchRequest(BaseModel):
    model: str
    provider: Optional[str] = None
    session_id: Optional[str] = None

class ModelParamsRequest(BaseModel):
    session_id: Optional[str] = None
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None
    top_p: Optional[float] = None
    reasoning: Optional[ReasoningConfig] = None
    thinking_budget: Optional[int] = None
    service_tier: Optional[str] = None

class ProviderCreateRequest(BaseModel):
    slug: str
    display_name: str = ""
    base_url: str
    api_key: str
    protocol: str = "openai"  
    context_length: int = 128000


# ── Sessions ─────────────────────────────────────────────────────────────────

class SessionCreateRequest(BaseModel):
    title: Optional[str] = None
    model: Optional[str] = None
    provider: Optional[str] = None

class SessionUpdateRequest(BaseModel):
    title: Optional[str] = None
    model: Optional[str] = None
    goal: Optional[str] = None

class SessionInfo(BaseModel):
    id: str
    title: Optional[str] = None
    model: str = ""
    provider: str = ""
    message_count: int = 0
    created: Optional[str] = None
    updated: Optional[str] = None
    has_checkpoints: bool = False

class SessionsListResponse(BaseModel):
    total: int
    sessions: list[SessionInfo]

class SessionHistoryResponse(BaseModel):
    session_id: str
    messages: list[dict]


# ── Skills ───────────────────────────────────────────────────────────────────

class SkillInfo(BaseModel):
    name: str
    category: str = ""
    description: str = ""
    tags: list[str] = []
    triggers: list[str] = []
    mitre_attack: list[str] = []
    nist_csf: list[str] = []
    source: Optional[str] = None
    file_path: str = ""

class SkillsListResponse(BaseModel):
    total: int
    skills: list[SkillInfo]

class SkillSearchRequest(BaseModel):
    query: str = ""
    mitre_tech: Optional[str] = None
    nist_csf: Optional[str] = None
    tool: Optional[str] = None
    category: Optional[str] = None
    limit: int = 10


# ── Tools ────────────────────────────────────────────────────────────────────

class ToolInfo(BaseModel):
    name: str
    toolset: str = ""
    enabled: bool = True
    description: str = ""

class ToolsListResponse(BaseModel):
    toolsets: list[str]
    tools: list[ToolInfo]

class ToolsModifyRequest(BaseModel):
    toolsets: Optional[list[str]] = None
    tools: Optional[list[str]] = None


# ── Config ───────────────────────────────────────────────────────────────────

class ConfigValueResponse(BaseModel):
    key: str
    value: Any
    type: str = "string"

class ConfigSetRequest(BaseModel):
    value: Any

class ConfigPatchRequest(BaseModel):
    updates: dict[str, Any]


# ── Gateway ──────────────────────────────────────────────────────────────────

class GatewayStatusResponse(BaseModel):
    running: bool
    pids: list[int] = []
    service: Optional[str] = None
    platform: str = ""
    uptime_seconds: int = 0
    profiles: list[str] = []

class GatewayActionRequest(BaseModel):
    force: bool = False
    drain_timeout: int = 30

class PlatformInfo(BaseModel):
    platform: str
    status: str
    chats: int = 0
    error: Optional[str] = None


# ── Profiles ─────────────────────────────────────────────────────────────────

class ProfileInfo(BaseModel):
    name: str
    home: str
    model: str = ""
    skills: int = 0
    gateway_running: bool = False

class ProfilesListResponse(BaseModel):
    active: str
    profiles: list[ProfileInfo]

class ProfileCreateRequest(BaseModel):
    name: str
    copy_from: Optional[str] = None


# ── System ──────────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str  # ok | degraded | error
    uptime: float = 0
    version: str = ""
    python: str = ""
    agent_status: str = "idle"
    active_sessions: int = 0

class StatusResponse(BaseModel):
    cpu_percent: float = 0
    memory_mb: float = 0
    open_files: int = 0
    threads: int = 0
    active_tasks: int = 0
    queued_tasks: int = 0

class UsageStatsResponse(BaseModel):
    period: str
    total_tokens: int = 0
    total_cost: float = 0
    by_model: dict = {}
    by_date: list = []


# ── Plugins ─────────────────────────────────────────────────────────────────

class PluginInfo(BaseModel):
    name: str
    version: str = ""
    description: str = ""
    status: str = "active"

class PluginInstallRequest(BaseModel):
    url: str
    branch: Optional[str] = None


# ── Cron ────────────────────────────────────────────────────────────────────

class CronJobInfo(BaseModel):
    id: str
    schedule: str
    prompt: str
    model: str = ""
    session_id: Optional[str] = None
    enabled: bool = True
    last_run: Optional[str] = None
    next_run: Optional[str] = None

class CronCreateRequest(BaseModel):
    schedule: str = Field(..., description="Cron expression (örn: '0 9 * * 1')")
    prompt: str = Field(..., description="Çalıştırılacak prompt")
    model: Optional[str] = None
    session_id: Optional[str] = None


# ── Files ───────────────────────────────────────────────────────────────────

class FileInfo(BaseModel):
    file_id: str
    name: str
    size: int
    type: str = ""
    path: str = ""
    uploaded_at: str = ""

class FileAnalyzeRequest(BaseModel):
    prompt: str = "Bu dosyayı analiz et"
    model: Optional[str] = None
    session_id: Optional[str] = None


# ── Error ────────────────────────────────────────────────────────────────────

class ErrorResponse(BaseModel):
    error: str
    code: str = "UNKNOWN"
    detail: Optional[str] = None
