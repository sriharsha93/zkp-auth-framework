from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel
import csv
import os
import re

from app.database import get_db
from app.models import User, OTPStore, SecurityLog
from app.security import (
    hash_password, verify_password,
    create_jwt_token, verify_jwt_token,
    generate_proof, verify_proof,
    generate_otp, get_otp_expiry
)

router = APIRouter()

# CSV file paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)
USERS_CSV = os.path.join(DATA_DIR, "users.csv")
LOGS_CSV = os.path.join(DATA_DIR, "security_logs.csv")
TOKENS_CSV = os.path.join(DATA_DIR, "tokens.csv")

# Lockout settings
MAX_LOGIN_ATTEMPTS = 3
LOGIN_LOCKOUT_MINUTES = 60
MAX_OTP_ATTEMPTS = 3
OTP_LOCKOUT_MINUTES = 60


# ============================================================
# PASSWORD VALIDATION
# ============================================================

def validate_password(password: str) -> dict:
    """
    Validate password meets all requirements.
    Returns {"valid": True/False, "errors": [list of errors]}
    """
    errors = []

    if len(password) < 8:
        errors.append("Password must be at least 8 characters long")
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least 1 uppercase letter (A-Z)")
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain at least 1 lowercase letter (a-z)")
    if not re.search(r'[0-9]', password):
        errors.append("Password must contain at least 1 number (0-9)")
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password):
        errors.append("Password must contain at least 1 special character (!@#$%^&*...)")

    return {"valid": len(errors) == 0, "errors": errors}


# ============================================================
# CSV HELPER FUNCTIONS
# ============================================================

def init_csv_files():
    if not os.path.exists(USERS_CSV):
        with open(USERS_CSV, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'user_id', 'username', 'email', 'reset_counter',
                'session_version', 'registered_at'
            ])
    if not os.path.exists(LOGS_CSV):
        with open(LOGS_CSV, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'log_id', 'user_id', 'event_type', 'details', 'timestamp'
            ])
    if not os.path.exists(TOKENS_CSV):
        with open(TOKENS_CSV, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'user_id', 'username', 'token', 'session_version',
                'issued_at', 'status'
            ])


def append_user_csv(user_id, username, email, reset_counter, session_version):
    init_csv_files()
    with open(USERS_CSV, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            user_id, username, email, reset_counter,
            session_version, datetime.now(timezone.utc).isoformat()
        ])


def append_log_csv(log_id, user_id, event_type, details):
    init_csv_files()
    with open(LOGS_CSV, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            log_id, user_id, event_type, details,
            datetime.now(timezone.utc).isoformat()
        ])


def append_token_csv(user_id, username, token, session_version, status="ACTIVE"):
    init_csv_files()
    with open(TOKENS_CSV, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            user_id, username, token[:50] + "...", session_version,
            datetime.now(timezone.utc).isoformat(), status
        ])


def update_user_csv_after_reset(user_id, username, email, new_rc, new_sv):
    init_csv_files()
    with open(USERS_CSV, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            user_id, username, email, new_rc,
            new_sv, f"UPDATED:{datetime.now(timezone.utc).isoformat()}"
        ])


def get_user_count_from_db(db: Session) -> int:
    return db.query(User).count()


def get_all_users_from_db(db: Session) -> list:
    users = db.query(User).all()
    return [
        {
            "user_id": u.id,
            "username": u.username,
            "email": u.email,
            "reset_counter": u.reset_counter,
            "session_version": u.session_version,
            "failed_login_attempts": u.failed_login_attempts,
            "failed_otp_attempts": u.failed_otp_attempts,
            "login_locked_until": str(u.login_locked_until) if u.login_locked_until else None,
            "otp_locked_until": str(u.otp_locked_until) if u.otp_locked_until else None,
            "created_at": str(u.created_at)
        }
        for u in users
    ]


# ============================================================
# LOCKOUT CHECK HELPERS
# ============================================================

def check_login_lockout(user: User) -> dict:
    """Check if user is locked out from login attempts."""
    if user.login_locked_until:
        lock_time = user.login_locked_until
        if lock_time.tzinfo is None:
            lock_time = lock_time.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        if now < lock_time:
            remaining = int((lock_time - now).total_seconds() / 60)
            return {
                "locked": True,
                "minutes_remaining": remaining + 1,
                "message": f"Account locked due to {MAX_LOGIN_ATTEMPTS} failed login attempts. "
                           f"Try again in {remaining + 1} minutes."
            }
        else:
            # Lockout expired, reset counter
            user.failed_login_attempts = 0
            user.login_locked_until = None
    return {"locked": False}


def check_otp_lockout(user: User) -> dict:
    """Check if user is locked out from OTP attempts."""
    if user.otp_locked_until:
        lock_time = user.otp_locked_until
        if lock_time.tzinfo is None:
            lock_time = lock_time.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        if now < lock_time:
            remaining = int((lock_time - now).total_seconds() / 60)
            return {
                "locked": True,
                "minutes_remaining": remaining + 1,
                "message": f"Password reset locked due to {MAX_OTP_ATTEMPTS} failed OTP attempts. "
                           f"Try again in {remaining + 1} minutes."
            }
        else:
            user.failed_otp_attempts = 0
            user.otp_locked_until = None
    return {"locked": False}


# ============================================================
# REQUEST MODELS
# ============================================================

class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

class ResetRequest(BaseModel):
    email: str

class VerifyOTPRequest(BaseModel):
    email: str
    otp: str
    proof: str

class ResetPasswordRequest(BaseModel):
    email: str
    new_password: str
    reset_token: str

class ReplayTestRequest(BaseModel):
    email: str
    old_proof: str


def log_event(db: Session, user_id: int, event_type: str, details: str):
    entry = SecurityLog(user_id=user_id, event_type=event_type, details=details)
    db.add(entry)
    db.commit()
    db.refresh(entry)
    append_log_csv(entry.id, user_id, event_type, details)


# ============================================================
# API ENDPOINTS
# ============================================================

# PASSWORD VALIDATION ENDPOINT (for real-time UI checking)
@router.post("/api/validate-password")
def validate_password_endpoint(data: dict):
    password = data.get("password", "")
    result = validate_password(password)
    return result


# 1. REGISTER
@router.post("/api/register")
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    existing = db.query(User).filter(
        (User.username == req.username) | (User.email == req.email)
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username or email already exists")
    if len(req.username) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters")

    # Validate password
    pwd_check = validate_password(req.password)
    if not pwd_check["valid"]:
        raise HTTPException(status_code=400, detail=" | ".join(pwd_check["errors"]))

    new_user = User(
        username=req.username,
        email=req.email,
        password_hash=hash_password(req.password),
        reset_counter=0,
        session_version=1,
        failed_login_attempts=0,
        failed_otp_attempts=0
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    append_user_csv(new_user.id, req.username, req.email, 0, 1)
    log_event(db, new_user.id, "REGISTRATION",
              f"User '{req.username}' registered. reset_counter=0, session_version=1")

    total_users = get_user_count_from_db(db)

    return {
        "message": "Registration successful",
        "user_id": new_user.id,
        "username": new_user.username,
        "reset_counter": new_user.reset_counter,
        "session_version": new_user.session_version,
        "total_registered_users": total_users
    }


# 2. LOGIN (with lockout)
@router.post("/api/login")
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == req.username).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    # Check lockout
    lockout = check_login_lockout(user)
    if lockout["locked"]:
        log_event(db, user.id, "LOGIN_BLOCKED",
                  f"Login attempt while locked. {lockout['minutes_remaining']} min remaining")
        db.commit()
        raise HTTPException(status_code=423, detail=lockout["message"])

    # Verify password
    if not verify_password(req.password, user.password_hash):
        user.failed_login_attempts += 1
        attempts_left = MAX_LOGIN_ATTEMPTS - user.failed_login_attempts

        if user.failed_login_attempts >= MAX_LOGIN_ATTEMPTS:
            user.login_locked_until = datetime.now(timezone.utc) + timedelta(minutes=LOGIN_LOCKOUT_MINUTES)
            db.commit()
            log_event(db, user.id, "ACCOUNT_LOCKED",
                      f"Account locked for {LOGIN_LOCKOUT_MINUTES} min after {MAX_LOGIN_ATTEMPTS} failed attempts")
            raise HTTPException(
                status_code=423,
                detail=f"Account locked! {MAX_LOGIN_ATTEMPTS} failed login attempts. "
                       f"Try again after {LOGIN_LOCKOUT_MINUTES} minutes."
            )
        else:
            db.commit()
            log_event(db, user.id, "LOGIN_FAILED",
                      f"Failed login attempt {user.failed_login_attempts}/{MAX_LOGIN_ATTEMPTS}")
            raise HTTPException(
                status_code=401,
                detail=f"Invalid password. {attempts_left} attempt(s) remaining before lockout."
            )

    # Successful login - reset failed attempts
    user.failed_login_attempts = 0
    user.login_locked_until = None
    db.commit()

    token = create_jwt_token(user.id, user.username, user.session_version)
    current_proof = generate_proof(user.password_hash, user.reset_counter)

    append_token_csv(user.id, user.username, token, user.session_version, "ACTIVE")
    log_event(db, user.id, "LOGIN_SUCCESS",
              f"User '{req.username}' logged in. session_version={user.session_version}")

    return {
        "message": "Login successful",
        "token": token,
        "user_id": user.id,
        "username": user.username,
        "reset_counter": user.reset_counter,
        "session_version": user.session_version,
        "current_proof": current_proof
    }


# 3. DASHBOARD
@router.get("/api/dashboard")
def dashboard(request: Request, db: Session = Depends(get_db)):
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="No token provided")

    token = auth.split(" ")[1]
    payload = verify_jwt_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user = db.query(User).filter(User.id == payload["user_id"]).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    if payload["session_version"] != user.session_version:
        append_token_csv(user.id, user.username, token, payload["session_version"], "REJECTED")
        log_event(db, user.id, "SESSION_REJECTED",
                  f"Token version ({payload['session_version']}) != DB version ({user.session_version})")
        raise HTTPException(
            status_code=401,
            detail=f"Session invalidated. Token version: {payload['session_version']}, "
                   f"Current version: {user.session_version}. Please login again."
        )

    return {
        "message": f"Welcome, {user.username}!",
        "user_id": user.id,
        "username": user.username,
        "reset_counter": user.reset_counter,
        "session_version": user.session_version,
        "token_session_version": payload["session_version"]
    }


# 4. REQUEST RESET
@router.post("/api/request-reset")
def request_reset(req: ResetRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="Email not found")

    # Check OTP lockout
    lockout = check_otp_lockout(user)
    if lockout["locked"]:
        log_event(db, user.id, "RESET_BLOCKED",
                  f"Reset attempt while locked. {lockout['minutes_remaining']} min remaining")
        db.commit()
        raise HTTPException(status_code=423, detail=lockout["message"])

    # Invalidate old OTPs
    db.query(OTPStore).filter(
        OTPStore.user_id == user.id, OTPStore.is_used == False
    ).update({"is_used": True})

    otp_code = generate_otp()
    otp_entry = OTPStore(
        user_id=user.id,
        otp_code=otp_code,
        expires_at=get_otp_expiry(),
        is_used=False
    )
    db.add(otp_entry)
    db.commit()

    current_proof = generate_proof(user.password_hash, user.reset_counter)

    log_event(db, user.id, "RESET_REQUESTED",
              f"OTP generated. reset_counter={user.reset_counter}. "
              f"Failed OTP attempts so far: {user.failed_otp_attempts}/{MAX_OTP_ATTEMPTS}")

    return {
        "message": "OTP generated successfully",
        "otp": otp_code,
        "expires_in_seconds": 120,
        "current_proof": current_proof,
        "reset_counter": user.reset_counter,
        "otp_attempts_used": user.failed_otp_attempts,
        "otp_attempts_max": MAX_OTP_ATTEMPTS,
        "note": "In production, OTP would be sent via email/SMS. Displayed here for demo."
    }


# 5. VERIFY OTP + PROOF (with lockout)
@router.post("/api/verify-otp")
def verify_otp(req: VerifyOTPRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Check OTP lockout
    lockout = check_otp_lockout(user)
    if lockout["locked"]:
        db.commit()
        raise HTTPException(status_code=423, detail=lockout["message"])

    otp_entry = db.query(OTPStore).filter(
        OTPStore.user_id == user.id, OTPStore.is_used == False
    ).order_by(OTPStore.created_at.desc()).first()

    if not otp_entry:
        raise HTTPException(status_code=400, detail="No valid OTP found. Request a new one.")

    # Check expiry
    now = datetime.now(timezone.utc)
    expires = otp_entry.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if now > expires:
        otp_entry.is_used = True
        db.commit()
        log_event(db, user.id, "OTP_EXPIRED", "OTP expired")
        raise HTTPException(status_code=400, detail="OTP expired. Request a new one.")

    # Check OTP code
    if otp_entry.otp_code != req.otp:
        user.failed_otp_attempts += 1
        attempts_left = MAX_OTP_ATTEMPTS - user.failed_otp_attempts

        if user.failed_otp_attempts >= MAX_OTP_ATTEMPTS:
            user.otp_locked_until = datetime.now(timezone.utc) + timedelta(minutes=OTP_LOCKOUT_MINUTES)
            otp_entry.is_used = True  # Invalidate the OTP
            db.commit()
            log_event(db, user.id, "OTP_LOCKED",
                      f"Password reset locked for {OTP_LOCKOUT_MINUTES} min after "
                      f"{MAX_OTP_ATTEMPTS} failed OTP attempts")
            raise HTTPException(
                status_code=423,
                detail=f"Password reset locked! {MAX_OTP_ATTEMPTS} failed OTP attempts. "
                       f"Try again after {OTP_LOCKOUT_MINUTES} minutes."
            )
        else:
            db.commit()
            log_event(db, user.id, "OTP_INVALID",
                      f"Wrong OTP. Attempt {user.failed_otp_attempts}/{MAX_OTP_ATTEMPTS}")
            raise HTTPException(
                status_code=400,
                detail=f"Invalid OTP code. {attempts_left} attempt(s) remaining before lockout."
            )

    # VERIFY ZKP PROOF
    if not verify_proof(req.proof, user.password_hash, user.reset_counter):
        log_event(db, user.id, "PROOF_FAILED",
                  f"ZKP proof failed for reset_counter={user.reset_counter}")
        raise HTTPException(
            status_code=400,
            detail="Proof verification failed. The cryptographic proof does not match the current state."
        )

    # SUCCESS - reset OTP attempt counter
    otp_entry.is_used = True
    user.failed_otp_attempts = 0
    user.otp_locked_until = None
    db.commit()

    reset_token = create_jwt_token(user.id, user.username, user.session_version)

    log_event(db, user.id, "VERIFICATION_SUCCESS",
              f"OTP + ZKP proof verified. reset_counter={user.reset_counter}")

    return {
        "message": "Verification successful. You may now reset your password.",
        "reset_token": reset_token,
        "proof_verified": True,
        "otp_verified": True
    }


# 6. RESET PASSWORD
@router.post("/api/reset-password")
def reset_password(req: ResetPasswordRequest, db: Session = Depends(get_db)):
    payload = verify_jwt_token(req.reset_token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired reset token")

    user = db.query(User).filter(User.email == req.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Validate new password
    pwd_check = validate_password(req.new_password)
    if not pwd_check["valid"]:
        raise HTTPException(status_code=400, detail=" | ".join(pwd_check["errors"]))

    old_rc = user.reset_counter
    old_sv = user.session_version
    old_proof = generate_proof(user.password_hash, user.reset_counter)

    user.password_hash = hash_password(req.new_password)
    user.reset_counter += 1
    user.session_version += 1
    db.commit()
    db.refresh(user)

    new_proof = generate_proof(user.password_hash, user.reset_counter)

    update_user_csv_after_reset(user.id, user.username, user.email,
                                 user.reset_counter, user.session_version)
    append_token_csv(user.id, user.username, "ALL_OLD_TOKENS",
                     old_sv, "REVOKED_AT_RESET")

    log_event(db, user.id, "PASSWORD_RESET_COMPLETE",
              f"reset_counter: {old_rc}->{user.reset_counter}, "
              f"session_version: {old_sv}->{user.session_version}")
    log_event(db, user.id, "SESSIONS_REVOKED",
              f"All sessions with version {old_sv} invalidated")

    return {
        "message": "Password reset successful. All previous sessions invalidated.",
        "old_reset_counter": old_rc,
        "new_reset_counter": user.reset_counter,
        "old_session_version": old_sv,
        "new_session_version": user.session_version,
        "old_proof": old_proof,
        "new_proof": new_proof,
        "sessions_revoked": True
    }


# 7. TEST REPLAY
@router.post("/api/test-replay")
def test_replay(req: ReplayTestRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    is_valid = verify_proof(req.old_proof, user.password_hash, user.reset_counter)
    expected = generate_proof(user.password_hash, user.reset_counter)

    if is_valid:
        return {
            "replay_blocked": False,
            "message": "Proof still valid (no reset since generated)",
            "current_reset_counter": user.reset_counter
        }
    else:
        log_event(db, user.id, "REPLAY_ATTACK_BLOCKED",
                  f"Replay blocked! reset_counter={user.reset_counter}")
        return {
            "replay_blocked": True,
            "message": "REPLAY ATTACK BLOCKED! Proof is no longer valid.",
            "submitted_proof": req.old_proof[:20] + "...",
            "expected_proof": expected[:20] + "...",
            "current_reset_counter": user.reset_counter,
            "reason": "reset_counter changed since this proof was generated"
        }


# 8. SECURITY LOGS
@router.get("/api/security-logs")
def get_logs(db: Session = Depends(get_db)):
    logs = db.query(SecurityLog).order_by(SecurityLog.timestamp.desc()).limit(50).all()
    return {
        "logs": [
            {
                "id": l.id,
                "user_id": l.user_id,
                "event_type": l.event_type,
                "details": l.details,
                "timestamp": str(l.timestamp)
            }
            for l in logs
        ]
    }


# 9. USER STATE
@router.get("/api/user-state/{username}")
def get_user_state(username: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    proof = generate_proof(user.password_hash, user.reset_counter)
    return {
        "username": user.username,
        "email": user.email,
        "reset_counter": user.reset_counter,
        "session_version": user.session_version,
        "failed_login_attempts": user.failed_login_attempts,
        "failed_otp_attempts": user.failed_otp_attempts,
        "login_locked_until": str(user.login_locked_until) if user.login_locked_until else None,
        "otp_locked_until": str(user.otp_locked_until) if user.otp_locked_until else None,
        "current_proof": proof,
        "created_at": str(user.created_at)
    }


# 10. ALL USERS
@router.get("/api/all-users")
def get_all_users(db: Session = Depends(get_db)):
    users = get_all_users_from_db(db)
    return {
        "total_users": len(users),
        "users": users
    }


# 11. DOWNLOAD CSV
@router.get("/api/download/users-csv")
def download_users_csv():
    init_csv_files()
    if not os.path.exists(USERS_CSV):
        raise HTTPException(status_code=404, detail="No user data yet")
    return FileResponse(USERS_CSV, media_type="text/csv", filename="users_data.csv")

@router.get("/api/download/logs-csv")
def download_logs_csv():
    init_csv_files()
    if not os.path.exists(LOGS_CSV):
        raise HTTPException(status_code=404, detail="No log data yet")
    return FileResponse(LOGS_CSV, media_type="text/csv", filename="security_logs.csv")

@router.get("/api/download/tokens-csv")
def download_tokens_csv():
    init_csv_files()
    if not os.path.exists(TOKENS_CSV):
        raise HTTPException(status_code=404, detail="No token data yet")
    return FileResponse(TOKENS_CSV, media_type="text/csv", filename="tokens_data.csv")
