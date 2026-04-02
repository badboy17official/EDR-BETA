import json
import asyncio
import aio_pika
import structlog
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from core.config import settings

logger = structlog.get_logger()

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type((aio_pika.exceptions.AMQPException, asyncio.TimeoutError)),
    reraise=True
)
async def publish_task(queue_name: str, payload: dict, timeout: int = 5):
    try:
        async def _publish():
            connection = await aio_pika.connect_robust(settings.RABBITMQ_URL)
            async with connection:
                channel = await connection.channel()
                # Ensure queue exists
                queue = await channel.declare_queue(queue_name, durable=True)
                
                message_body = json.dumps(payload).encode()
                message = aio_pika.Message(
                    body=message_body,
                    delivery_mode=aio_pika.DeliveryMode.PERSISTENT
                )
                
                await channel.default_exchange.publish(
                    message,
                    routing_key=queue_name,
                )
                logger.info("message_published", queue=queue_name, task_id=payload.get("task_id"))

        # Add timeout to broker publish operation
        await asyncio.wait_for(_publish(), timeout=timeout)
            
    except asyncio.TimeoutError:
        logger.error("rabbitmq_publish_timeout", queue=queue_name, payload=payload)
        raise
    except Exception as e:
        logger.error("rabbitmq_publish_failed", error=str(e), payload=payload)
        raise
