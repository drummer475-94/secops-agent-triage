from pydantic import BaseModel, Field


class ReasoningStep(BaseModel):
    step_number: int
    action: str
    observation: str
    deduction: str
    confidence: float = Field(ge=0.0, le=1.0)
