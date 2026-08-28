# AEGIS Module 2: Agent Authorization - API Router

import logging
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field

from modules.agent_auth.engine import EXAMPLE_POLICY, PolicyEngine

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/agent", tags=["agent-auth"])

# Singleton engine
_engine: PolicyEngine | None = None


def get_engine() -> PolicyEngine:
    global _engine
    if _engine is None:
        _engine = PolicyEngine()
    return _engine


# --- Request/Response Models ---


class ToolCall(BaseModel):
    tool: str = Field(..., description="Tool name being called")
    params: dict = Field(default_factory=dict, description="Tool parameters")


class SessionContext(BaseModel):
    user_id: str | None = None
    role: str | None = None
    organization_id: str | None = None
    session_id: str | None = None
    extra: dict = Field(default_factory=dict)


class AuthorizeRequest(BaseModel):
    agent_id: str = Field(..., description="The agent making the tool call")
    tool_call: ToolCall
    session: SessionContext = Field(default_factory=SessionContext)


class PolicyCondition(BaseModel):
    key: str
    operator: str = "eq"
    value: str = ""


class PolicyResource(BaseModel):
    path: str
    actions: list[str] = Field(default_factory=list)
    conditions: list[PolicyCondition] = Field(default_factory=list)


class PolicyCreate(BaseModel):
    name: str = Field(..., max_length=255)
    description: str | None = Field(None, max_length=1000)
    agent_id: str | None = None
    resources: list[PolicyResource] = Field(default_factory=list)
    priority: int = Field(default=100, ge=0, le=1000)
    default_action: str = Field(default="deny", pattern="^(allow|deny)$")


class PolicyResponse(BaseModel):
    id: str
    name: str
    description: str | None
    agent_id: str | None
    resources: list[dict]
    priority: int
    active: bool
    version: int
    created_at: str


class AuthorizeResponse(BaseModel):
    authorized: bool
    policy_id: str | None = None
    policy_name: str | None = None
    conditions_met: bool = True
    denied_reason: str | None = None
    latency_ms: float = 0.0


# --- Routes ---


@router.post("/authorize", response_model=AuthorizeResponse)
async def authorize_tool_call(
    request: AuthorizeRequest,
    x_api_key: str | None = Header(None),
    engine: PolicyEngine = Depends(get_engine),
):
    """Authorize a single agent tool call against configured policies."""
    if not request.agent_id.strip():
        raise HTTPException(status_code=400, detail="agent_id is required")

    # Build context for policy evaluation
    context = {
        "auth": (
            request.session.model_dump(exclude_none=True) if request.session else {}
        ),
        "tool_call": {
            "tool": request.tool_call.tool,
            "params": request.tool_call.params,
        },
    }

    # In production, policies are loaded from the database
    policies = [EXAMPLE_POLICY]

    result = engine.authorize_tool_call(
        agent_id=request.agent_id,
        tool_name=request.tool_call.tool,
        tool_params=request.tool_call.params,
        policies=policies,
        context=context,
    )

    return AuthorizeResponse(
        authorized=result.authorized,
        policy_id=result.policy_id,
        policy_name=result.policy_name,
        conditions_met=result.conditions_met,
        denied_reason=result.denied_reason,
        latency_ms=result.latency_ms,
    )


@router.post("/policies", response_model=PolicyResponse, status_code=201)
async def create_policy(
    policy: PolicyCreate,
    x_api_key: str | None = Header(None),
):
    """Create a new authorization policy. (Stub - DB integration pending)"""
    # TODO: Store in database
    return PolicyResponse(
        id=str(uuid.uuid4()),
        name=policy.name,
        description=policy.description,
        agent_id=policy.agent_id,
        resources=[r.model_dump() for r in policy.resources],
        priority=policy.priority,
        active=True,
        version=1,
        created_at=datetime.now(UTC).isoformat(),
    )


@router.get("/policies")
async def list_policies():
    """List all policies. (Stub)"""
    return {"policies": [EXAMPLE_POLICY], "count": 1}


@router.get("/health")
async def health_check():
    return {"module": "agent_auth", "status": "healthy", "version": "1.0.0"}
