"""
MailForensics — Database Seeding Script
Creates default administrative and analyst accounts for the platform.
"""
import uuid
import datetime
from sqlalchemy.orm import Session
from app.database import engine, SessionLocal, Base
from app.models.models import User
from app.core.security import get_password_hash

DEFAULT_USERS = [
    {
        "email": "admin@mailforensics.local",
        "password": "Admin@123456",
        "full_name": "SOC Administrator",
        "role": "ADMIN"
    },
    {
        "email": "analyst@mailforensics.local",
        "password": "Analyst@123456",
        "full_name": "Tier-2 SOC Analyst",
        "role": "ANALYST"
    }
]

def seed_default_users(db: Session = None):
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        # Ensure tables exist
        Base.metadata.create_all(bind=engine)

        created = []
        for user_data in DEFAULT_USERS:
            existing = db.query(User).filter(User.email == user_data["email"].lower()).first()
            if not existing:
                user = User(
                    id=str(uuid.uuid4()),
                    email=user_data["email"].lower(),
                    hashed_password=get_password_hash(user_data["password"]),
                    full_name=user_data["full_name"],
                    role=user_data["role"],
                    is_active=True
                )
                db.add(user)
                created.append(user_data["email"])
        
        if created:
            db.commit()
            print(f"Successfully seeded users: {', '.join(created)}")
        else:
            print("Default users already exist in the database.")
    finally:
        if close_db:
            db.close()

if __name__ == "__main__":
    seed_default_users()
