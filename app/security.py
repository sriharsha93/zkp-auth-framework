import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt
from passlib.context import CryptContext

# Configuration
JWT_SECRET_KEY = "zkp-auth-framework-secret-key-2024"
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_MINUTES = 30
HMAC_SECRET_KEY = "zkp-hmac-secret-key-2024"
OTP_LENGTH = 6
OTP_EXPIRY_SECONDS = 120

# Password hashing using bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_jwt_token(user_id: int, username: str, session_version: int) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "user_id": user_id,
        "username": username,
        "session_version": session_version,
        "exp": now + timedelta(minutes=JWT_EXPIRATION_MINUTES),
        "iat": now
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def verify_jwt_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError:
        return None


def generate_proof(password_hash: str, reset_counter: int) -> str:
    """
    ZKP-style proof: HMAC-SHA256(password_hash, secret:reset_counter)
    The proof changes when reset_counter changes, preventing replay attacks.
    """
    message = f"{HMAC_SECRET_KEY}:{reset_counter}"
    proof = hmac.new(
        password_hash.encode('utf-8'),
        message.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    return proof


def verify_proof(submitted_proof: str, password_hash: str, reset_counter: int) -> bool:
    expected_proof = generate_proof(password_hash, reset_counter)
    return hmac.compare_digest(submitted_proof, expected_proof)


def generate_otp() -> str:
    otp = secrets.randbelow(10 ** OTP_LENGTH)
    return str(otp).zfill(OTP_LENGTH)


def get_otp_expiry() -> datetime:
    return datetime.now(timezone.utc) + timedelta(seconds=OTP_EXPIRY_SECONDS)
