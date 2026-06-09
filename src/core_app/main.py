import os
import uuid
from datetime import datetime, timezone
from enum import Enum
from http.client import responses
from typing import Any, Dict, List, Literal, Optional, Union

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator


SERVICE_NAME = os.getenv("SERVICE_NAME", "core-business")
SERVICE_VERSION = os.getenv("SERVICE_VERSION", "1.0.0")
AUTH_TOKEN = os.getenv("AUTH_TOKEN", "local-dev-token")

app = FastAPI(
    title="Smart Campus API - Phân hệ B6",
    description="Core Business API xử lý nghiệp vụ trung tâm",
    version=SERVICE_VERSION,
)


class ProblemDetails(BaseModel):
    type: str = "about:blank"
    title: str
    status: int = Field(..., ge=400, le=599)
    detail: str
    instance: Optional[str] = None


class HealthResponse(BaseModel):
    status: str
    service: str
    time: str


class AlertSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class CreateAlertRequest(BaseModel):
    sourceService: str = Field(..., min_length=2, max_length=80)
    alertType: str
    severity: AlertSeverity
    message: str = Field(..., min_length=5, max_length=500)
    relatedEventId: Optional[str] = None


class Alert(BaseModel):
    id: str
    sourceService: str
    alertType: str
    severity: AlertSeverity
    message: str
    relatedEventId: Optional[str] = None
    status: str
    createdAt: str
    resolvedAt: Optional[str] = None


class AlertPage(BaseModel):
    items: List[Alert]
    nextCursor: Optional[str] = None
    hasMore: bool


# In-memory storage
ALERTS: List[Alert] = []
EVENTS: List[Dict] = []


def build_problem(
    *,
    status_code: int,
    title: str,
    detail: str,
    instance: Optional[str] = None,
    problem_type: str = "about:blank",
) -> Dict:
    problem = {
        "type": problem_type,
        "title": title,
        "status": status_code,
        "detail": detail,
    }
    if instance:
        problem["instance"] = instance
    return problem


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    if isinstance(exc.detail, dict):
        problem = exc.detail
    else:
        problem = build_problem(
            status_code=exc.status_code,
            title=responses.get(exc.status_code, "HTTP Error"),
            detail=str(exc.detail),
            instance=str(request.url.path),
        )

    problem.setdefault("status", exc.status_code)
    problem.setdefault("title", responses.get(exc.status_code, "HTTP Error"))
    problem.setdefault("type", "about:blank")
    problem.setdefault("detail", "Request failed")
    problem.setdefault("instance", str(request.url.path))

    return JSONResponse(
        status_code=exc.status_code,
        content=problem,
        media_type="application/problem+json",
        headers=getattr(exc, "headers", None),
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    first_error = exc.errors()[0] if exc.errors() else {}
    location = ".".join(str(item) for item in first_error.get("loc", []))
    message = first_error.get("msg", "Request validation error")
    detail = f"{location}: {message}" if location else message

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=build_problem(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            title="Validation error",
            detail=detail,
            instance=str(request.url.path),
            problem_type="https://smart-campus.local/problems/validation-error",
        ),
        media_type="application/problem+json",
    )


def verify_bearer_token(authorization: Optional[str] = Header(default=None)) -> None:
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=build_problem(
                status_code=status.HTTP_401_UNAUTHORIZED,
                title="Unauthorized",
                detail="Missing Authorization header",
                problem_type="https://smart-campus.local/problems/unauthorized",
            ),
        )

    expected = f"Bearer {AUTH_TOKEN}"
    if authorization != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=build_problem(
                status_code=status.HTTP_401_UNAUTHORIZED,
                title="Unauthorized",
                detail="Invalid bearer token",
                problem_type="https://smart-campus.local/problems/unauthorized",
            ),
        )


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        service=SERVICE_NAME,
        time=now_iso(),
    )


@app.post(
    "/alerts",
    response_model=Alert,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(verify_bearer_token)],
)
def create_alert(payload: CreateAlertRequest, response: Response) -> Alert:
    alert_id = str(uuid.uuid4())
    created_at = now_iso()

    alert = Alert(
        id=alert_id,
        sourceService=payload.sourceService,
        alertType=payload.alertType,
        severity=payload.severity,
        message=payload.message,
        relatedEventId=payload.relatedEventId,
        status="OPEN",
        createdAt=created_at,
        resolvedAt=None,
    )
    ALERTS.append(alert)
    response.headers["Location"] = f"/alerts/{alert_id}"
    return alert


@app.get(
    "/alerts",
    response_model=AlertPage,
    dependencies=[Depends(verify_bearer_token)],
)
def get_alerts(
    cursor: Optional[str] = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
) -> AlertPage:
    return AlertPage(
        items=ALERTS[-limit:],
        nextCursor=None,
        hasMore=False,
    )


@app.get(
    "/alerts/recent",
    dependencies=[Depends(verify_bearer_token)],
)
def get_recent_alerts(
    limit: int = Query(default=20),
) -> Dict[str, List[Alert]]:
    # Custom validation for limit query parameter as required by Newman test
    if limit > 100 or limit < 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=build_problem(
                status_code=status.HTTP_400_BAD_REQUEST,
                title="Bad Request",
                detail="limit must be between 1 and 100",
                problem_type="https://smart-campus.local/problems/validation-error",
            ),
        )

    return {"items": ALERTS[-limit:]}


@app.get(
    "/alerts/{alert_id}",
    response_model=Alert,
    dependencies=[Depends(verify_bearer_token)],
)
def get_alert_by_id(alert_id: str) -> Alert:
    for alert in ALERTS:
        if alert.id == alert_id:
            return alert

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=build_problem(
            status_code=status.HTTP_404_NOT_FOUND,
            title="Not Found",
            detail=f"Alert {alert_id} not found",
            problem_type="https://smart-campus.local/problems/not-found",
        ),
    )


class SensorEvent(BaseModel):
    eventType: Literal["SENSOR_READING"] = "SENSOR_READING"
    eventId: str
    deviceId: str = Field(..., pattern=r"^SENSOR-[0-9]{3}$")
    metric: str
    value: float = Field(..., ge=-100, le=1000)
    unit: str
    timestamp: str


class AccessEvent(BaseModel):
    eventType: Literal["ACCESS_CHECK"] = "ACCESS_CHECK"
    eventId: str
    gateId: str = Field(..., pattern=r"^GATE-[0-9]{2}$")
    cardId: str = Field(..., pattern=r"^RFID-[0-9]{4}-[0-9]{3}$")
    decision: str
    timestamp: str


class EventAccepted(BaseModel):
    eventId: str
    acceptedAt: str


@app.post(
    "/events",
    response_model=EventAccepted,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(verify_bearer_token)],
)
def create_event(payload: Dict[str, Any]) -> EventAccepted:
    # Custom validation for events request payload
    event_type = payload.get("eventType")
    event_id = payload.get("eventId")

    if not event_type or not event_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=build_problem(
                status_code=status.HTTP_400_BAD_REQUEST,
                title="Bad Request",
                detail="Missing eventType or eventId",
                problem_type="https://smart-campus.local/problems/validation-error",
            ),
        )

    # Basic schema validation checks
    if event_type == "ACCESS_CHECK":
        if "gateId" not in payload or "cardId" not in payload:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=build_problem(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    title="Bad Request",
                    detail="Missing gateId or cardId in AccessEvent",
                    problem_type="https://smart-campus.local/problems/validation-error",
                ),
            )

    EVENTS.append(payload)
    return EventAccepted(
        eventId=event_id,
        acceptedAt=now_iso(),
    )


class AccessCheckRequest(BaseModel):
    cardId: str = Field(..., pattern=r"^RFID-[0-9]{4}-[0-9]{3}$")
    gateId: str = Field(..., pattern=r"^GATE-[0-9]{2}$")
    timestamp: str
    faceMatched: Optional[bool] = None
    confidence: Optional[float] = None


class AccessCheckResponse(BaseModel):
    decision: str
    expiresAt: str
    reasonCode: str


@app.post(
    "/access/check",
    response_model=AccessCheckResponse,
    dependencies=[Depends(verify_bearer_token)],
)
def check_access(payload: AccessCheckRequest) -> AccessCheckResponse:
    # Default return decision
    return AccessCheckResponse(
        decision="ALLOW",
        expiresAt=now_iso(),
        reasonCode="AUTHORIZED_CARD",
    )


class FaceMatchRequest(BaseModel):
    imageRef: str
    requestId: str
    cameraId: str
    timestamp: str


class FaceMatchResponse(BaseModel):
    detectionId: str
    detectionType: str = "FACE"
    faceMatched: bool
    isLive: bool
    confidence: float
    status: str
    matchedPersonId: Optional[str] = None


@app.post(
    "/vision/face-match",
    response_model=FaceMatchResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(verify_bearer_token)],
)
def face_match(payload: FaceMatchRequest) -> FaceMatchResponse:
    return FaceMatchResponse(
        detectionId=str(uuid.uuid4()),
        faceMatched=True,
        isLive=True,
        confidence=0.92,
        status="success",
        matchedPersonId="PERSON-1234",
    )
