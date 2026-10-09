import pytest
import os
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.main import app
from app.database import Base, get_db
from app.core.security import get_password_hash, create_access_token
from app.models.models import User

TEST_DB_URL = "sqlite:///./test_mailforensics.db"

engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)
    if os.path.exists("./test_mailforensics.db"):
        try:
            os.remove("./test_mailforensics.db")
        except Exception:
            pass

@pytest.fixture
def db_session():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

@pytest.fixture
def client(db_session):
    def _override_get_db():
        try:
            yield db_session
        finally:
            pass
    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as c:
        yield c

@pytest.fixture
def test_user(db_session):
    user = db_session.query(User).filter(User.email == "analyst@mailforensics.test").first()
    if not user:
        user = User(
            email="analyst@mailforensics.test",
            hashed_password=get_password_hash("TestPassword123!"),
            full_name="Test Analyst",
            role="ANALYST"
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)
    return user

@pytest.fixture
def auth_headers(test_user):
    token = create_access_token({"sub": test_user.id, "role": test_user.role})
    return {"Authorization": f"Bearer {token}"}
