from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class ScanRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        v = str(value).strip()
        if not v:
            raise ValueError("url is required")
        return v


class ScanResponse(BaseModel):
    id: int
    url: str
    normalized_url: Optional[str] = None
    score: int = Field(..., ge=0, le=100)
    verdict: str
    reason: str
    reason_details: List[str] = Field(default_factory=list)
    features: Dict[str, Any] = Field(default_factory=dict)
    model_version: str = "rule_v1"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    persisted: bool = False
    label: Optional[str] = None
    ml_proba: Optional[float] = None
    ml_proba_local: Optional[float] = None
    ml_proba_public: Optional[float] = None
    safe_mode: Dict[str, Any] = Field(default_factory=dict)
    llm_summary: str | None = None
    model_config = {"from_attributes": True}


class LabelRequest(BaseModel):
    label: str = Field(..., pattern="^(malicious|safe|unknown)$")


class DatasetRow(BaseModel):
    id: int
    url: str
    label: str
    features: Dict[str, Any]
    created_at: datetime

    model_config = {"from_attributes": True}
