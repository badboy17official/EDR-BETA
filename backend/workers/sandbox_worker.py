import asyncio
import json
import logging
import os
import sys

# Ensure we can import from backend root
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import aio_pika
from sqlalchemy.future import select
from db.session import AsyncSessionLocal
from db.models import TaskStatus, Reputation, FileMetadata, DynamicFeatures
from sandbox.runner import SandboxRunner

logging.basicConfig(level=logging.INFO, format="%(asctime)s - [SandboxWorker] - %(levelname)s - %(message)s")
logger = logging.getLogger("SandboxWorker")

RABBITMQ_URL = os.getenv("RABBITMQ_URL", "amqp://guest:guest@localhost/")
UPLOADS_DIR = "/tmp/sandbox_uploads"

async def process_sandbox_task(message: aio_pika.IncomingMessage):
    async with message.process():
        body = json.loads(message.body.decode())
        task_id = body.get("task_id")
        file_hash = body.get("file_hash")
        
        logger.info(f"Received sandbox task for {file_hash} (Task: {task_id})")
        
        filepath = os.path.join(UPLOADS_DIR, f"{file_hash}.bin")
        
        if not os.path.exists(filepath):
            logger.error(f"File {filepath} not found for dynamic analysis.")
            return

        # 1. Run the Sandbox
        runner = SandboxRunner()
        try:
            logger.info(f"Executing payload {filepath} in isolated sandbox...")
            report = runner.analyze_file(filepath, timeout=30)
        except Exception as e:
            logger.error(f"Sandbox execution failed: {e}")
            return
            
        logger.info(f"Sandbox Report for {file_hash}: {report}")
        
        # 2. Update Database with Behavior Report
        async with AsyncSessionLocal() as session:
            # Save Dynamic Features
            dynamic = DynamicFeatures(
                task_id=task_id,
                sha256=file_hash,
                risk_score=float(report.get("risk_score", 0)),
                network_activity=report.get("network_activity", False),
                suspicious_actions=json.dumps(report.get("suspicious_actions", [])),
                syscalls=json.dumps(report.get("syscalls", {}))
            )
            session.add(dynamic)
            
            # Recalculate Reputation
            result = await session.execute(select(Reputation).where(Reputation.sha256 == file_hash))
            rep = result.scalars().first()
            
            if rep:
                # Combine ML score and Sandbox Score strictly
                # For example, if ML classified as suspicious, but sandbox sees huge risk, bump to malicious
                dyn_score = float(report.get("risk_score", 0)) * 10 
                combined_score = rep.risk_score + dyn_score
                
                rep.risk_score = min(100.0, combined_score)
                
                if rep.risk_score > 75.0:
                    rep.is_malicious = True
                    rep.classification = "malicious"
                    rep.confidence_score = min(100.0, rep.confidence_score + dyn_score)
                elif rep.risk_score > 40.0:
                    rep.classification = "suspicious"
            
            await session.commit()
            logger.info(f"Updated dynamic reputation for {file_hash}. New score: {rep.risk_score if rep else 'N/A'}")

async def consume():
    logger.info("Connecting to RabbitMQ...")
    connection = await aio_pika.connect_robust(RABBITMQ_URL)
    
    async with connection:
        channel = await connection.channel()
        await channel.set_qos(prefetch_count=2) # Processing is heavy, limit concurrency
        
        queue = await channel.declare_queue("sandbox-queue", durable=True)
        logger.info("[*] Waiting for sandbox tasks. To exit press CTRL+C")
        
        await queue.consume(process_sandbox_task)
        await asyncio.Future() # Run forever

if __name__ == "__main__":
    asyncio.run(consume())