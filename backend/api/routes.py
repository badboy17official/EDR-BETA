from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Depends, File, UploadFile, Request
import structlog
import uuid
import hashlib
import pathlib
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from core.schemas import APIResponse
from core.cache import cache_client
from broker.producer import publish_task
from db.models import FileMetadata, Reputation, TaskStatus
from db.session import get_db_session

logger = structlog.get_logger()
router = APIRouter()

@router.post("/upload", response_model=APIResponse)
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db_session),
):
    try:
        # File type / sanitization validation
        filename = file.filename or "unknown"
        ext = pathlib.Path(filename).suffix.lower()
        if ext not in settings.ALLOWED_EXTENSIONS:
            return APIResponse(status="error", error={"message": f"Unsupported file extension: {ext}"})

        sanitized_name = pathlib.Path(filename).name

        # Agent Tracking
        agent_id = request.state.agent_id

        # Stream file, hash, and write to temporary object storage buffer.
        sha256_hash = hashlib.sha256()
        file_size = 0
        temp_dir = Path("/tmp/object-store-staging")
        temp_dir.mkdir(parents=True, exist_ok=True)
        temp_file_path = temp_dir / f"upload-{uuid.uuid4().hex}"

        with open(temp_file_path, "wb") as temp_file:
            while chunk := await file.read(65536):
                file_size += len(chunk)
                if file_size > settings.MAX_UPLOAD_SIZE:
                    temp_file_path.unlink(missing_ok=True)
                    return APIResponse(status="error", error={"message": "File exceeds maximum allowed size"})
                sha256_hash.update(chunk)
                temp_file.write(chunk)
            
        final_hash = sha256_hash.hexdigest()

        existing_stmt = select(FileMetadata).where(FileMetadata.sha256 == final_hash)
        existing_file = (await db.execute(existing_stmt)).scalar_one_or_none()
        if existing_file is not None:
            logger.info(
                "upload_deduplicated",
                sha256=final_hash,
                task_id=existing_file.task_id,
                status=existing_file.status.value if existing_file.status else None,
                agent_id=agent_id,
            )
            temp_file_path.unlink(missing_ok=True)
            return APIResponse(
                status="success",
                data={
                    "deduplicated": True,
                    "sha256": final_hash,
                    "task_id": existing_file.task_id,
                    "status": existing_file.status.value if existing_file.status else TaskStatus.PENDING.value,
                },
            )

        task_id = str(uuid.uuid4())

        object_store_dir = Path("/tmp/object-store")
        object_store_dir.mkdir(parents=True, exist_ok=True)
        object_path = object_store_dir / final_hash
        temp_file_path.replace(object_path)

        new_file = FileMetadata(
            sha256=final_hash,
            size=file_size,
            mime_type=file.content_type,
            first_seen=datetime.utcnow(),
            task_id=task_id,
            status=TaskStatus.PENDING,
            agent_id=agent_id,
        )
        db.add(new_file)
        await db.commit()

        metadata = {
            "sha256": final_hash,
            "filename": sanitized_name,
            "size": file_size,
            "status": TaskStatus.PENDING.value,
            "task_id": task_id,
            "agent_id": agent_id,
        }
        
        # 2. Enqueue tasks to RabbitMQ Queue
        payload = {
            "task_id": task_id,
            "sha256": final_hash,
            "s3_path": f"/tmp/object-store/{final_hash}",
        }
        
        await publish_task("static-analysis-queue", payload)
        logger.info(
            "file_uploaded_for_scanning",
            sha256=final_hash,
            task_id=task_id,
            agent_id=agent_id,
            file_size=file_size,
        )
        
        return APIResponse(status="success", data=metadata)

    except Exception as e:
        logger.error("file_upload_failed", error=str(e))
        return APIResponse(status="error", error={"message": "File processing failed"})

@router.get("/hash/{sha256}", response_model=APIResponse)
async def lookup_hash(sha256: str, db: AsyncSession = Depends(get_db_session)):
    logger.info("hash_lookup", sha256=sha256)

    cached = await cache_client.get_json(f"hash:{sha256}")
    if cached is not None:
        return APIResponse(status="success", data={**cached, "cache_hit": True, "found": True})

    rep_stmt = select(Reputation).where(Reputation.sha256 == sha256)
    rep = (await db.execute(rep_stmt)).scalar_one_or_none()
    if rep is None:
        return APIResponse(
            status="success",
            data={"sha256": sha256, "found": False, "classification": "unknown", "cache_hit": False},
        )

    data = {
        "sha256": rep.sha256,
        "is_malicious": bool(rep.is_malicious),
        "classification": rep.classification,
        "risk_score": float(rep.risk_score or 0.0),
        "confidence_score": float(rep.confidence_score or 0.0),
        "frequency": int(rep.frequency or 0),
        "first_seen": rep.first_seen.isoformat() if rep.first_seen else None,
        "last_seen": rep.last_seen.isoformat() if rep.last_seen else None,
        "cache_hit": False,
        "found": True,
    }
    await cache_client.set_json(f"hash:{sha256}", data, ttl_seconds=24 * 3600)
    return APIResponse(status="success", data=data)

@router.get("/report/{task_id}", response_model=APIResponse)
async def get_scan_report(task_id: str, db: AsyncSession = Depends(get_db_session)):
    logger.info("report_requested", task_id=task_id)

    file_stmt = select(FileMetadata).where(FileMetadata.task_id == task_id)
    file_obj = (await db.execute(file_stmt)).scalar_one_or_none()
    if file_obj is None:
        return APIResponse(status="error", error={"message": "Task not found", "code": "TASK_NOT_FOUND"})

    report_data = {
        "task_id": task_id,
        "sha256": file_obj.sha256,
        "status": file_obj.status.value if file_obj.status else TaskStatus.PENDING.value,
    }

    if file_obj.status in (TaskStatus.PENDING, TaskStatus.PROCESSING):
        report_data["poll_after_seconds"] = settings.REPORT_POLL_BASE_DELAY_SEC

    if file_obj.status == TaskStatus.COMPLETED:
        from db.models import Reputation, DynamicFeatures
        import json
        rep_stmt = select(Reputation).where(Reputation.sha256 == file_obj.sha256)
        rep = (await db.execute(rep_stmt)).scalar_one_or_none()
        
        dyn_stmt = select(DynamicFeatures).where(DynamicFeatures.sha256 == file_obj.sha256)
        dyn = (await db.execute(dyn_stmt)).scalar_one_or_none()

        if rep is not None:
            report_data.update(
                {
                    "classification": rep.classification,
                    "is_malicious": bool(rep.is_malicious),
                    "risk_score": float(rep.risk_score or 0.0),
                    "confidence_score": float(rep.confidence_score or 0.0),
                }
            )
        if dyn is not None:
            report_data["sandbox_results"] = {
                "dynamic_risk": float(dyn.risk_score or 0.0),
                "network_activity": bool(dyn.network_activity),
                "suspicios_actions": json.loads(dyn.suspicious_actions) if dyn.suspicious_actions else [],
                "syscalls_summary": json.loads(dyn.syscalls) if dyn.syscalls else {}
            }

    return APIResponse(status="success", data=report_data)
