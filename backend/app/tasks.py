import asyncio
import logging
from app.celery_app import celery_app
from app.database import SessionLocal

logger = logging.getLogger(__name__)

@celery_app.task(name="app.tasks.analyze_email_task", bind=True)
def analyze_email_task(self, email_id: str):
    """
    Celery task executing full email forensic investigation pipeline in worker process.
    Emits real-time WebSocket frames, processes headers, YARA, URLs, attachments, and risk scoring.
    """
    logger.info(f"Celery worker started email analysis task for: {email_id}")
    db = SessionLocal()
    try:
        from app.api.emails import execute_email_analysis_pipeline
        # Run async pipeline in worker thread event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(execute_email_analysis_pipeline(email_id, db))
        loop.close()
        logger.info(f"Celery worker finished email analysis for: {email_id}")
        return {"status": "SUCCESS", "email_id": email_id}
    except Exception as e:
        logger.error(f"Celery worker failed on email {email_id}: {e}")
        return {"status": "FAILED", "email_id": email_id, "error": str(e)}
    finally:
        db.close()
