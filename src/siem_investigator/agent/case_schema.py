"""Case-level decisions; source facts and chronology are resolved by code."""
from pydantic import BaseModel, ConfigDict, Field
from .stages import IntrusionStage

class CaseAction(BaseModel):
    model_config = ConfigDict(extra="forbid")
    stage: IntrusionStage
    subject_event_ids: list[str] = Field(min_length=1)
    context_event_ids: list[str] = Field(default_factory=list)
    interpretation: str = Field(description="Qualified interpretation only, not an observed fact. No time arithmetic or unsupported causal assertion.")
    limitations: list[str] = Field(default_factory=list)

class ActionGroup(BaseModel):
    model_config = ConfigDict(extra="forbid")
    actions: list[CaseAction] = Field(min_length=1)

class EventDisposition(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_ids: list[str] = Field(min_length=1)
    reason: str

class CaseReview(BaseModel):
    model_config = ConfigDict(extra="forbid")
    findings: list[ActionGroup]
    context: list[EventDisposition] = Field(default_factory=list)
    unresolved: list[EventDisposition] = Field(default_factory=list)
    unrelated_event_ids: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
