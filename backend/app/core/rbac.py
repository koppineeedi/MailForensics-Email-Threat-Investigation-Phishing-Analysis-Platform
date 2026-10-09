from fastapi import HTTPException, status, Depends
from typing import List
from app.models.models import User

ROLE_ADMIN = "ADMIN"
ROLE_ANALYST = "ANALYST"
ROLE_VIEWER = "VIEWER"

ROLE_HIERARCHY = {
    ROLE_ADMIN: 3,
    ROLE_ANALYST: 2,
    ROLE_VIEWER: 1
}

def require_role(allowed_roles: List[str]):
    def role_checker(current_user: User):
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation not permitted. Required role: {allowed_roles}, Current role: {current_user.role}"
            )
        return current_user
    return role_checker

def check_permission(user_role: str, min_required_role: str) -> bool:
    user_level = ROLE_HIERARCHY.get(user_role, 0)
    required_level = ROLE_HIERARCHY.get(min_required_role, 3)
    return user_level >= required_level
