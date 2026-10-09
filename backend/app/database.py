import logging
from typing import Dict, Any, Tuple
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker, declarative_base
from app.config import settings

logger = logging.getLogger(__name__)

is_sqlite = settings.DATABASE_URL.startswith("sqlite")
is_postgres = settings.DATABASE_URL.startswith("postgresql")

# Configure engine with production-ready connection pooling when on PostgreSQL
if is_sqlite:
    engine = create_engine(
        settings.DATABASE_URL,
        connect_args={"check_same_thread": False},
        echo=False
    )
    # Enable foreign keys for SQLite
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()
else:
    engine = create_engine(
        settings.DATABASE_URL,
        pool_size=settings.DATABASE_POOL_SIZE,
        max_overflow=settings.DATABASE_MAX_OVERFLOW,
        pool_pre_ping=settings.DATABASE_POOL_PRE_PING,
        pool_recycle=settings.DATABASE_POOL_RECYCLE,
        echo=False
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def check_db_connection() -> Dict[str, Any]:
    """
    Validate database connection and return detailed status.
    Guaranteed not to raise an unhandled exception.
    """
    status_info = {
        "engine": "postgresql" if is_postgres else ("sqlite" if is_sqlite else "unknown"),
        "status": "UNAVAILABLE",
        "pool_size": settings.DATABASE_POOL_SIZE if is_postgres else None,
        "detail": None
    }
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
            status_info["status"] = "HEALTHY"
            status_info["detail"] = "Database connection verified successfully"
    except Exception as e:
        status_info["status"] = "ERROR"
        status_info["detail"] = f"Database connection failed: {str(e)}"
        logger.error(f"Database health check error: {e}")
    return status_info
