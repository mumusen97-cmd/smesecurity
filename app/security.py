from fastapi import Header, HTTPException

from app.models import Role


def get_role(x_role: str = Header(default="")) -> Role:
    candidate = x_role.strip().lower()
    valid_roles = {r.value for r in Role}
    if candidate not in valid_roles:
        raise HTTPException(status_code=401, detail="Missing or invalid X-Role header")
    return Role(candidate)


def require_role(role: Role, allowed: set[Role]) -> None:
    if role not in allowed:
        raise HTTPException(status_code=403, detail="Role is not permitted for this action")
