import asyncio
import json
import os
import tempfile
import structlog
import aio_pika
from tenacity import retry, stop_after_attempt, wait_exponential
from sqlalchemy import select

# Adjusts Python path to import from parent directory correctly if run via script
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from core.config import settings
from services.static_analyzer import analyze_file
from broker.producer import publish_task
from db.models import TaskStatus, FileMetadata, StaticFeatures
from db.session import AsyncSessionLocal

# Standardize JSON logger 
structlog.configure(
    processors=[
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ]
)
logger = structlog.get_logger()

async def update_task_status(task_id: str, status: TaskStatus):
    async with AsyncSessionLocal() as session:
        stmt = select(FileMetadata).where(FileMetadata.task_id == task_id)
        obj = (await session.execute(stmt)).scalar_one_or_none()
        if obj is not None:
            obj.status = status
            await session.commit()
    logger.info("db_task_status_update", task_id=task_id, status=status.value)

async def simulate_s3_download(s3_path: str, temp_filepath: str):
    """
    Mock function simulating pulling the file from S3.
    In real app, this would use aiobotocore or boto3.
    For this mock, we just write some fake "ELF/PE" bytes to the temp file.
    """
    await asyncio.sleep(0.1)
    if os.path.exists(s3_path):
        with open(s3_path, "rb") as src, open(temp_filepath, "wb") as dst:
            dst.write(src.read())
        return

    # Fallback simulation when local object path is missing.
    with open(temp_filepath, "wb") as f:
        f.write(b"\x7fELF\x02\x01\x01\x00some_random_bytes_for_entropy_here_HelloWorld")
        
async def save_features_to_db(task_id: str, sha256: str, features: dict):
    """Persist extracted static features."""
    safe_imports = features.get("imports", [])[:200]
    raw = json.dumps(
        {
            "imports": safe_imports,
            "metadata": features.get("metadata", {}),
        }
    )

    async with AsyncSessionLocal() as session:
        stmt = select(StaticFeatures).where(StaticFeatures.task_id == task_id)
        existing = (await session.execute(stmt)).scalar_one_or_none()
        if existing is None:
            existing = StaticFeatures(task_id=task_id, sha256=sha256)
            session.add(existing)

        existing.file_type = features.get("file_type", "UNKNOWN")
        existing.entropy = float(features.get("entropy", 0.0))
        existing.imports_count = int(features.get("imports_count", 0))
        existing.strings_count = int(features.get("strings_count", 0))
        existing.raw_data = raw
        await session.commit()

    summary = {
        "file_type": features["file_type"],
        "entropy": features["entropy"],
        "imports": features["imports_count"],
        "strings": features["strings_count"]
    }
    logger.info("db_saved_static_features", task_id=task_id, sha256=sha256, summary=summary)

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
async def process_analysis(payload: dict):
    """Encapsulates the actual work, making it retryable via Tenacity."""
    task_id = payload.get("task_id")
    sha256 = payload.get("sha256")
    s3_path = payload.get("s3_path")
    
    await update_task_status(task_id, TaskStatus.PROCESSING)
    
    # 1. Retrieve the file
    with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
        temp_filepath = tmp_file.name
        
    try:
        # Simulate boto3 S3 GET
        await simulate_s3_download(s3_path, temp_filepath)
        
        # 2. Perform Static Analysis (CPU Bound, usually wrapped in run_in_executor for heavy loads)
        # We run it synchronously here as it's just Python standard libs + LIEF
        features = analyze_file(temp_filepath)
        
        # 3. Store in Postgres
        await save_features_to_db(task_id, sha256, features)
        
        # 4. Enqueue for ML evaluation
        next_payload = {
            "task_id": task_id,
            "sha256": sha256,
            "static_results": features # Payload contains needed ML features
        }
        await publish_task("ml-inference-queue", next_payload)
        
        # Keep task in PROCESSING until ML stage finalizes verdict.
        logger.info("static_analysis_pipeline_success", task_id=task_id)

    except Exception as e:
        logger.error("static_analysis_pipeline_error", task_id=task_id, error=str(e))
        await update_task_status(task_id, TaskStatus.FAILED)
        raise e # Reraise to trigger Tenacity retry or RabbitMQ Nack
    
    finally:
        # Clean up temporary file
        if os.path.exists(temp_filepath):
            os.remove(temp_filepath)

async def consume_messages():
    """RabbitMQ consumer loop."""
    logger.info("starting_static_worker", queue="static-analysis-queue")
    
    try:
        connection = await aio_pika.connect_robust(settings.RABBITMQ_URL)
        async with connection:
            channel = await connection.channel()
            # Prevent overwhelming the worker
            await channel.set_qos(prefetch_count=10)
            
            queue = await channel.declare_queue("static-analysis-queue", durable=True)
            
            async with queue.iterator() as queue_iter:
                async for message in queue_iter:
                    async with message.process(ignore_action_exceptions=True):
                        try:
                            payload = json.loads(message.body.decode())
                            logger.info("message_received", task_id=payload.get("task_id"))
                            
                            # Execute the retryable bounds
                            await process_analysis(payload)
                            
                        except Exception as e:
                            logger.error("message_abandoned", error=str(e))
                            # Message will be rejected and potentially put in DLQ (Dead Letter Queue)
                            
    except Exception as connection_error:
        logger.error("rabbitmq_connection_failed", error=str(connection_error))
        raise

if __name__ == "__main__":
    try:
        asyncio.run(consume_messages())
    except KeyboardInterrupt:
        logger.info("worker_shutdown_requested")
