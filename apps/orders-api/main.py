"""
KubeShield orders-api: Hardened Microservice
Designed for execution in a restricted Kubernetes environment:
- Non-root user (UID 10001)
- Read-only root filesystem with ephemeral /tmp
- Dropped Linux capabilities
- Credentials synced securely via External Secrets Operator from KMS/Secrets Manager
"""

import os
import sys
import time
import uuid
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List

from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST

# -----------------------------------------------------------------------------
# Structured JSON Logger Configuration (Security-Auditable)
# -----------------------------------------------------------------------------
class JSONFormatter(logging.Formatter):
    """Formats log records as single-line JSON objects for SIEM ingestion."""
    def format(self, record: logging.LogRecord) -> str:
        log_obj: Dict[str, Any] = {
            # time.strftime() does not support %f, so build the ISO-8601 UTC timestamp via datetime
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "level": record.levelname,
            "service": "orders-api",
            "environment": os.getenv("ENVIRONMENT", "k8s-hardened"),
            "logger": record.name,
            "message": record.getMessage(),
            "pid": os.getpid(),
        }

        # Check UID if running on POSIX
        if hasattr(os, "getuid"):
            log_obj["uid"] = os.getuid()
            log_obj["gid"] = os.getgid()

        if hasattr(record, "extra_data") and isinstance(record.extra_data, dict):
            log_obj.update(record.extra_data)

        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_obj)

logger = logging.getLogger("orders-api")
logger.setLevel(logging.INFO)
logger.handlers.clear()
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(JSONFormatter())
logger.addHandler(console_handler)

def log_event(level: str, message: str, **kwargs):
    extra = {"extra_data": kwargs}
    if level == "INFO":
        logger.info(message, extra=extra)
    elif level in ("WARN", "WARNING"):
        logger.warning(message, extra=extra)
    elif level == "ERROR":
        logger.error(message, extra=extra)
    else:
        logger.debug(message, extra=extra)

# -----------------------------------------------------------------------------
# Metrics Definition
# -----------------------------------------------------------------------------
REQUEST_COUNT = Counter(
    "http_requests_total",
    "Total HTTP requests processed",
    ["method", "path", "status", "app"],
)
REQUEST_DURATION_SECONDS = Histogram(
    "http_request_duration_seconds",
    "HTTP request latency in seconds",
    ["method", "path", "app"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5),
)
IN_FLIGHT_REQUESTS = Gauge(
    "http_requests_in_flight",
    "Number of concurrent HTTP requests",
    ["app"],
)
ORDERS_TOTAL = Counter(
    "orders_created_total",
    "Total order creation transactions",
    ["status", "app"],
)

# -----------------------------------------------------------------------------
# FastAPI App Initialization
# -----------------------------------------------------------------------------
app = FastAPI(
    title="KubeShield Orders API",
    version="1.0.0",
    description="Hardened microservice running under Pod Security Admission Restricted profile",
)

# -----------------------------------------------------------------------------
# Data Models & Database Mock
# -----------------------------------------------------------------------------
class OrderCreate(BaseModel):
    customer_id: str = Field(..., min_length=1, max_length=64, examples=["cust_shield_401"])
    items: List[Dict[str, Any]] = Field(
        default_factory=lambda: [{"sku": "yubikey-5c", "quantity": 2, "price": 55.00}],
        examples=[[{"sku": "yubikey-5c", "quantity": 2, "price": 55.00}]],
    )
    total_amount: float = Field(default=110.00, ge=0, examples=[110.00])

ORDERS_DB: Dict[str, Dict[str, Any]] = {
    "ord-1001": {
        "order_id": "ord-1001",
        "customer_id": "cust_demo",
        "items": [{"sku": "nitrokey-pro", "quantity": 1, "price": 60.00}],
        "total_amount": 60.00,
        "status": "SETTLED",
        "created_at": 1776000000.0,
    }
}

# -----------------------------------------------------------------------------
# Middleware for Telemetry and Access Logging
# -----------------------------------------------------------------------------
@app.middleware("http")
async def security_telemetry_middleware(request: Request, call_next):
    trace_id = request.headers.get("X-Trace-ID", str(uuid.uuid4()))
    client_ip = request.client.host if request.client else "unknown"
    path = request.url.path
    method = request.method

    if path == "/metrics":
        return await call_next(request)

    IN_FLIGHT_REQUESTS.labels(app="orders-api").inc()
    start_time = time.time()
    status_code = 500

    try:
        response = await call_next(request)
        status_code = response.status_code
        return response
    except Exception as exc:
        status_code = 500
        log_event(
            "ERROR",
            f"Unhandled exception during request: {exc}",
            trace_id=trace_id,
            method=method,
            path=path,
            client_ip=client_ip,
        )
        raise
    finally:
        duration_sec = time.time() - start_time
        # Label metrics by route template (e.g. /api/v1/orders/{order_id}) to keep cardinality bounded
        route = request.scope.get("route")
        metric_path = getattr(route, "path", "unmatched")
        IN_FLIGHT_REQUESTS.labels(app="orders-api").dec()
        REQUEST_COUNT.labels(method=method, path=metric_path, status=str(status_code), app="orders-api").inc()
        REQUEST_DURATION_SECONDS.labels(method=method, path=metric_path, app="orders-api").observe(duration_sec)

        level = "INFO" if status_code < 400 else ("WARN" if status_code < 500 else "ERROR")
        log_event(
            level,
            f"HTTP {method} {path} - {status_code}",
            trace_id=trace_id,
            method=method,
            path=path,
            status_code=status_code,
            latency_ms=round(duration_sec * 1000, 2),
            client_ip=client_ip,
        )

# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------
@app.get("/healthz", summary="Liveness Probe")
def healthz():
    return {
        "status": "healthy",
        "service": "orders-api",
        "timestamp": time.time(),
    }

@app.get("/ready", summary="Readiness Probe")
def ready():
    # Verify required environment configuration
    db_host = os.getenv("DB_HOST", "mock-postgres")
    return {
        "status": "ready",
        "service": "orders-api",
        "database_target": db_host,
    }

@app.get("/metrics", summary="Prometheus Metrics")
def metrics():
    return PlainTextResponse(generate_latest(), media_type=CONTENT_TYPE_LATEST)

@app.get("/api/v1/security-status", summary="Runtime Security Assessment")
def security_status():
    """
    Returns non-sensitive security details confirming container isolation,
    non-root execution, and Secret sync status.
    """
    uid = os.getuid() if hasattr(os, "getuid") else -1
    gid = os.getgid() if hasattr(os, "getgid") else -1

    # Check rootfs writeability (should fail if readOnlyRootFilesystem=true)
    is_rootfs_read_only = False
    try:
        with open("/rootfs_write_probe.tmp", "w") as f:
            f.write("test")
        os.remove("/rootfs_write_probe.tmp")
    except (IOError, PermissionError, OSError):
        is_rootfs_read_only = True

    # Check ephemeral tmp writeability (mounted emptyDir at /tmp)
    tmp_writable = False
    try:
        test_file = f"/tmp/probe_{uuid.uuid4().hex[:6]}.tmp"
        with open(test_file, "w") as f:
            f.write("ok")
        if os.path.exists(test_file):
            os.remove(test_file)
            tmp_writable = True
    except Exception:
        tmp_writable = False

    # Check whether External Secrets synced DB secrets into env
    db_user = os.getenv("DB_USER")
    db_password = os.getenv("DB_PASSWORD")
    secrets_loaded = bool(db_user and db_password)

    return {
        "runtime": {
            "uid": uid,
            "gid": gid,
            "is_non_root": uid != 0,
            "read_only_rootfs": is_rootfs_read_only,
            "tmp_storage_writable": tmp_writable,
        },
        "secrets": {
            "synced_from_external_secrets": secrets_loaded,
            "db_user_configured": db_user if db_user else "NOT_FOUND",
            "db_password_masked": f"{db_password[:2]}***{db_password[-2:]}" if db_password and len(db_password) > 4 else ("CONFIGURED" if db_password else "NOT_FOUND"),
            "db_host": os.getenv("DB_HOST", "postgres.internal"),
            "db_name": os.getenv("DB_NAME", "orders_db"),
        },
        "pod_security_standard": "restricted",
    }

@app.get("/api/v1/orders", summary="List All Orders")
def list_orders():
    return {
        "orders": list(ORDERS_DB.values()),
        "count": len(ORDERS_DB),
    }

@app.post("/api/v1/orders", status_code=status.HTTP_201_CREATED, summary="Create an Order")
def create_order(order: OrderCreate):
    order_id = f"ord-{uuid.uuid4().hex[:8]}"
    record = {
        "order_id": order_id,
        "customer_id": order.customer_id,
        "items": order.items,
        "total_amount": order.total_amount,
        "status": "CONFIRMED",
        "created_at": time.time(),
    }
    ORDERS_DB[order_id] = record
    ORDERS_TOTAL.labels(status="success", app="orders-api").inc()

    log_event(
        "INFO",
        f"Order {order_id} recorded successfully",
        order_id=order_id,
        customer_id=order.customer_id,
        total_amount=order.total_amount,
    )
    return record

@app.get("/api/v1/orders/{order_id}", summary="Get Order Details")
def get_order(order_id: str):
    if order_id not in ORDERS_DB:
        raise HTTPException(status_code=404, detail=f"Order {order_id} not found")
    return ORDERS_DB[order_id]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_config=None)
