import base64
import json
import os
import secrets
from datetime import datetime, timedelta, timezone

import jwt
from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from app.models import Actor, AuthResult, CredentialRecord, Role, UserAccount

#storing users in memory for now, will move to db later
USERS: dict[str, UserAccount] = {}
#temp storage for challenges during registration and login
PENDING_REGISTRATION: dict[str, dict] = {}
PENDING_AUTHENTICATION: dict[str, bytes] = {}


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


#pull secret from env so we dont hardcode it
def _jwt_secret() -> str:
    return os.getenv("APP_SECRET_KEY", "change-this-secret-before-production")


def _token_ttl_minutes() -> int:
    return int(os.getenv("APP_TOKEN_TTL_MINUTES", "120"))


def webauthn_rp_id() -> str:
    return os.getenv("WEBAUTHN_RP_ID", "localhost")


def webauthn_origin() -> str:
    return os.getenv("WEBAUTHN_ORIGIN", "http://localhost:8000")


def webauthn_rp_name() -> str:
    return os.getenv("WEBAUTHN_RP_NAME", "OWASP SME Security Platform")


#signs a jwt with the users role and an expiry time
def issue_access_token(username: str, role: Role) -> str:
    payload = {
        "sub": username,
        "role": role.value,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=_token_ttl_minutes()),
    }
    return jwt.encode(payload, _jwt_secret(), algorithm="HS256")


#decodes the token and returns an actor object for rbac checks
def verify_access_token(token: str) -> Actor:
    payload = jwt.decode(token, _jwt_secret(), algorithms=["HS256"])
    return Actor(
        username=str(payload["sub"]),
        role=Role(str(payload["role"])),
        auth_method="bearer",
    )


def get_user(username: str) -> UserAccount | None:
    return USERS.get(username)


def get_profile(actor: Actor) -> dict[str, str]:
    user = get_user(actor.username)
    display_name = user.display_name if user else actor.username
    return {
        "username": actor.username,
        "display_name": display_name,
        "role": actor.role.value,
        "auth_method": actor.auth_method,
    }


#step 1 of webauthn - generate the challenge and send options to browser
def registration_options(username: str, display_name: str, role: Role) -> dict:
    existing = USERS.get(username)
    user_id_bytes = secrets.token_bytes(16) if not existing else base64url_to_bytes(existing.user_id)
    exclude_credentials = []
    if existing:
        exclude_credentials = [
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(cred.credential_id))
            for cred in existing.credentials
        ]

    options = generate_registration_options(
        rp_id=webauthn_rp_id(),
        rp_name=webauthn_rp_name(),
        user_id=user_id_bytes,
        user_name=username,
        user_display_name=display_name,
        challenge=secrets.token_bytes(32),
        exclude_credentials=exclude_credentials,
        #platform forces windows hello instead of usb key
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )
    payload = json.loads(options_to_json(options))
    #save the challenge so we can verify it when the browser responds
    PENDING_REGISTRATION[username] = {
        "challenge": base64url_to_bytes(payload["challenge"]),
        "display_name": display_name,
        "role": role,
        "user_id": payload["user"]["id"],
    }
    return payload


#step 2 of webauthn - verify what the browser sent back matches our challenge
def verify_registration(username: str, credential: dict) -> AuthResult:
    pending = PENDING_REGISTRATION.get(username)
    if not pending:
        raise ValueError("No registration challenge found for user")

    verification = verify_registration_response(
        credential=credential,
        expected_challenge=pending["challenge"],
        expected_rp_id=webauthn_rp_id(),
        expected_origin=webauthn_origin(),
        #set to false to match preferred policy, true was causing 500 errors
        require_user_verification=False,
    )

    #save the public key - we never store the private key, it stays on the device
    record = CredentialRecord(
        credential_id=_b64url_encode(verification.credential_id),
        public_key=_b64url_encode(verification.credential_public_key),
        sign_count=verification.sign_count,
        device_type=str(verification.credential_device_type),
        backed_up=bool(verification.credential_backed_up),
        transports=credential.get("response", {}).get("transports", []),
    )

    #create new account or add credential to existing one
    account = USERS.get(username)
    if account is None:
        account = UserAccount(
            username=username,
            display_name=str(pending["display_name"]),
            role=pending["role"],
            user_id=str(pending["user_id"]),
            credentials=[record],
        )
    else:
        account.display_name = str(pending["display_name"])
        account.role = pending["role"]
        account.credentials.append(record)
    USERS[username] = account
    #clean up the pending challenge once done
    PENDING_REGISTRATION.pop(username, None)

    return AuthResult(
        access_token=issue_access_token(account.username, account.role),
        username=account.username,
        display_name=account.display_name,
        role=account.role,
    )


#login step 1 - check the user exists then send them a challenge
def authentication_options(username: str) -> dict:
    user = USERS.get(username)
    if user is None or not user.credentials:
        raise ValueError("User does not have a registered passkey")

    options = generate_authentication_options(
        rp_id=webauthn_rp_id(),
        challenge=secrets.token_bytes(32),
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(cred.credential_id))
            for cred in user.credentials
        ],
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    payload = json.loads(options_to_json(options))
    PENDING_AUTHENTICATION[username] = base64url_to_bytes(payload["challenge"])
    return payload


#login step 2 - verify the signed challenge and return a token
def verify_authentication(username: str, credential: dict) -> AuthResult:
    user = USERS.get(username)
    if user is None:
        raise ValueError("Unknown user")

    challenge = PENDING_AUTHENTICATION.get(username)
    if challenge is None:
        raise ValueError("No authentication challenge found for user")

    #make sure the credential they sent is one we registered for this user
    credential_id = credential.get("id", "")
    record = next((cred for cred in user.credentials if cred.credential_id == credential_id), None)
    if record is None:
        raise ValueError("Credential is not registered for this user")

    verification = verify_authentication_response(
        credential=credential,
        expected_challenge=challenge,
        expected_rp_id=webauthn_rp_id(),
        expected_origin=webauthn_origin(),
        credential_public_key=base64url_to_bytes(record.public_key),
        credential_current_sign_count=record.sign_count,
        require_user_verification=False,
    )
    #update sign count to detect cloned credentials
    record.sign_count = verification.new_sign_count
    PENDING_AUTHENTICATION.pop(username, None)

    return AuthResult(
        access_token=issue_access_token(user.username, user.role),
        username=user.username,
        display_name=user.display_name,
        role=user.role,
    )