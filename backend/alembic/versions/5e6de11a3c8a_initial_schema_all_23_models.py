"""Initial_schema_all_23_models

Revision ID: 5e6de11a3c8a
Revises: 
Create Date: 2026-09-29 16:12:23.121963

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from app.database import Base
import app.models.models

# revision identifiers, used by Alembic.
revision: str = '5e6de11a3c8a'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    """Create all 23 MailForensics relational tables."""
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)

def downgrade() -> None:
    """Drop all tables."""
    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind)
