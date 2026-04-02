from fastapi import FastAPI, Depends, Request, HTTPException, Security, Header
from fastapi.security import APIKeyHeader
from fastapi.responses import JSONResponse
import structlog
import time
import bcrypt

from core.config import settings
from core.schemas import APIResponse
from api.routes import router as api_router

# Structured Logger setup
structlog.configure(
    processors=[
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ]
)
logger = structlog.get_logger()

# Security Auth
api_key_header = APIKeyHeader(name="X-Agent-Key", auto_error=True)

def verify_api_key(
    request: Request,
    api_key: str = Security(api_key_header),
    agent_id: str = Header(..., alias="X-Agent-ID")
):
    # Verify API key using bcrypt against the hashed secret stored in config
    try:
        is_valid = bcrypt.checkpw(api_key.encode('utf-8'), settings.AGENT_API_HASH.encode('utf-8'))
        if not is_valid:
            raise ValueError()
    except Exception:
        logger.warning("unauthorized_api_access_attempt", agent_id=agent_id)
        raise HTTPException(status_code=401, detail={"status": "error", "error": {"message": "Unauthorized Agent"}})
    
    # Track the agent ID in the request state for routing endpoints
    request.state.agent_id = agent_id
    return agent_id

# Dependency for global route protections
app = FastAPI(
    title=settings.PROJECT_NAME
)

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Middleware --- #
@app.middleware("http")
async def logging_middleware(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    duration = time.time() - start_time
    
    # Only logging valid endpoints
    logger.info(
        "http_request",
        method=request.method,
        url=str(request.url),
        status_code=response.status_code,
        duration=round(duration, 4),
        agent_id=getattr(request.state, "agent_id", "unknown")
    )
    
    return response

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("unhandled_server_exception", error=str(exc), path=str(request.url))
    return JSONResponse(
        status_code=500, 
        content={"status": "error", "error": {"message": "Internal Server Error"}}
    )

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # If the exception detail is already our standard dict, use it
    detail = exc.detail if isinstance(exc.detail, dict) else {"message": str(exc.detail)}
    return JSONResponse(
        status_code=exc.status_code,
        content={"status": "error", "error": detail}
    )

# Register Routers
app.include_router(
    api_router, 
    prefix=settings.API_V1_STR, 
    dependencies=[Depends(verify_api_key)]
)

from api.dashboard_routes import router as dashboard_router
app.include_router(dashboard_router, prefix="/api/dashboard")

from fastapi.staticfiles import StaticFiles
import os

# Serve static dashboard
frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.exists(frontend_path):
    app.mount("/dashboard", StaticFiles(directory=frontend_path, html=True), name="frontend")

@app.get("/health")
async def health_check():
    return APIResponse(status="success", data={"version": "1.0.0"})
