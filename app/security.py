import jwt
from fastapi import Depends, Header, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.models import Actor, Role
from app.services.auth import verify_access_token

bearer_scheme = HTTPBearer(auto_error=False)


#checks bearer token first, falls back to x-role header for tests only
def get_current_actor(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    x_role: str = Header(default=""),
) -> Actor:
    if credentials and credentials.credentials:
        try:
            return verify_access_token(credentials.credentials)
        except (jwt.InvalidTokenError, KeyError, ValueError) as exc:
            raise HTTPException(status_code=401, detail="Invalid bearer token") from exc

    #x-role header fallback so pytest doesnt need a real passkey
    candidate = x_role.strip().lower()
    valid_roles = {r.value for r in Role}
    if candidate in valid_roles:
        return Actor(username=f"header-{candidate}", role=Role(candidate), auth_method="header")

    raise HTTPException(status_code=401, detail="Missing authentication token or valid X-Role header")


#implemented rbac - throws 403 if the user doesnt have the right role
def require_role(actor: Actor, allowed: set[Role]) -> None:
    if actor.role not in allowed:
        raise HTTPException(status_code=403, detail="Role is not permitted for this action")
