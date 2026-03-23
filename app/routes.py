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

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)
USERS_CSV = os.path.join(DATA_DIR, "users.csv")
LOGS_CSV = os.path.join(DATA_DIR, "security_logs.csv")
TOKENS_CSV = os.path.join(DATA_DIR, "tokens.csv")
CREDENTIALS_CSV = os.path.join(DATA_DIR, "credentials.csv")

MAX_LOGIN_ATTEMPTS = 3
LOGIN_LOCKOUT_MINUTES = 60
MAX_OTP_ATTEMPTS = 3
OTP_LOCKOUT_MINUTES = 60


def validate_password(password: str) -> dict:
    errors = []
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long")
    if not re.search(r'[A-Z]', password):
        errors.append("Must contain at least 1 uppercase letter (A-Z)")
    if not re.search(r'[a-z]', password):
        errors.append("Must contain at least 1 lowercase letter (a-z)")
    if not re.search(r'[0-9]', password):
        errors.append("Must contain at least 1 number (0-9)")
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password):
        errors.append("Must contain at least 1 special character")
    return {"valid": len(errors) == 0, "errors": errors}


# ============================================================
# CSV HELPERS
# ============================================================

def init_csv_files():
    if not os.path.exists(USERS_CSV):
        with open(USERS_CSV, 'w', newline='') as f:
            csv.writer(f).writerow(['user_id','username','email','reset_counter','session_version','registered_at'])
    if not os.path.exists(LOGS_CSV):
        with open(LOGS_CSV, 'w', newline='') as f:
            csv.writer(f).writerow(['log_id','user_id','event_type','details','timestamp'])
    if not os.path.exists(TOKENS_CSV):
        with open(TOKENS_CSV, 'w', newline='') as f:
            csv.writer(f).writerow(['user_id','username','type','value','session_version','issued_at','status'])
    if not os.path.exists(CREDENTIALS_CSV):
        with open(CREDENTIALS_CSV, 'w', newline='') as f:
            csv.writer(f).writerow(['user_id','username','email','event','password_hash','proof','reset_counter','session_version','timestamp'])


def append_csv(filepath, row):
    init_csv_files()
    with open(filepath, 'a', newline='') as f:
        csv.writer(f).writerow(row)


def save_credential_event(user_id, username, email, event, pwd_hash, proof, rc, sv):
    append_csv(CREDENTIALS_CSV, [
        user_id, username, email, event, pwd_hash, proof, rc, sv,
        datetime.now(timezone.utc).isoformat()
    ])


def save_token_record(user_id, username, rec_type, value, sv, status):
    append_csv(TOKENS_CSV, [
        user_id, username, rec_type, value, sv,
        datetime.now(timezone.utc).isoformat(), status
    ])


# ============================================================
# LOCKOUT HELPERS
# ============================================================

def check_login_lockout(user):
    if user.login_locked_until:
        lock_time = user.login_locked_until
        if lock_time.tzinfo is None:
            lock_time = lock_time.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        if now < lock_time:
            remaining = int((lock_time - now).total_seconds() / 60) + 1
            return {"locked": True, "minutes_remaining": remaining,
                    "message": f"Account locked ({MAX_LOGIN_ATTEMPTS} failed attempts). Try in {remaining} min."}
        else:
            user.failed_login_attempts = 0
            user.login_locked_until = None
    return {"locked": False}


def check_otp_lockout(user):
    if user.otp_locked_until:
        lock_time = user.otp_locked_until
        if lock_time.tzinfo is None:
            lock_time = lock_time.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        if now < lock_time:
            remaining = int((lock_time - now).total_seconds() / 60) + 1
            return {"locked": True, "minutes_remaining": remaining,
                    "message": f"Reset locked ({MAX_OTP_ATTEMPTS} failed OTP attempts). Try in {remaining} min."}
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


def log_event(db, user_id, event_type, details):
    entry = SecurityLog(user_id=user_id, event_type=event_type, details=details)
    db.add(entry)
    db.commit()
    db.refresh(entry)
    append_csv(LOGS_CSV, [entry.id, user_id, event_type, details, datetime.now(timezone.utc).isoformat()])


# ============================================================
# API ENDPOINTS
# ============================================================

@router.post("/api/validate-password")
def validate_password_endpoint(data: dict):
    return validate_password(data.get("password", ""))


@router.post("/api/register")
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    existing = db.query(User).filter((User.username == req.username) | (User.email == req.email)).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username or email already exists")
    if len(req.username) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
    pwd_check = validate_password(req.password)
    if not pwd_check["valid"]:
        raise HTTPException(status_code=400, detail=" | ".join(pwd_check["errors"]))

    pwd_hash = hash_password(req.password)
    new_user = User(username=req.username, email=req.email, password_hash=pwd_hash,
                    reset_counter=0, session_version=1, failed_login_attempts=0, failed_otp_attempts=0)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    proof = generate_proof(pwd_hash, 0)

    append_csv(USERS_CSV, [new_user.id, req.username, req.email, 0, 1, datetime.now(timezone.utc).isoformat()])
    save_credential_event(new_user.id, req.username, req.email, "REGISTER", pwd_hash, proof, 0, 1)
    save_token_record(new_user.id, req.username, "PROOF", proof, 1, "INITIAL")

    log_event(db, new_user.id, "REGISTRATION",
              f"User '{req.username}' registered. Hash: {pwd_hash[:20]}... Proof: {proof[:20]}...")

    return {"message": "Registration successful", "user_id": new_user.id, "username": new_user.username,
            "reset_counter": 0, "session_version": 1, "total_registered_users": db.query(User).count()}


@router.post("/api/login")
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == req.username).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    lockout = check_login_lockout(user)
    if lockout["locked"]:
        log_event(db, user.id, "LOGIN_BLOCKED", f"Locked. {lockout['minutes_remaining']} min remaining")
        db.commit()
        raise HTTPException(status_code=423, detail=lockout["message"])

    if not verify_password(req.password, user.password_hash):
        user.failed_login_attempts += 1
        left = MAX_LOGIN_ATTEMPTS - user.failed_login_attempts
        if user.failed_login_attempts >= MAX_LOGIN_ATTEMPTS:
            user.login_locked_until = datetime.now(timezone.utc) + timedelta(minutes=LOGIN_LOCKOUT_MINUTES)
            db.commit()
            log_event(db, user.id, "ACCOUNT_LOCKED", f"Locked for {LOGIN_LOCKOUT_MINUTES} min")
            raise HTTPException(status_code=423, detail=f"Account locked! Try after {LOGIN_LOCKOUT_MINUTES} minutes.")
        db.commit()
        log_event(db, user.id, "LOGIN_FAILED", f"Attempt {user.failed_login_attempts}/{MAX_LOGIN_ATTEMPTS}")
        raise HTTPException(status_code=401, detail=f"Invalid password. {left} attempt(s) left.")

    user.failed_login_attempts = 0
    user.login_locked_until = None
    db.commit()

    token = create_jwt_token(user.id, user.username, user.session_version)
    proof = generate_proof(user.password_hash, user.reset_counter)

    save_token_record(user.id, user.username, "TOKEN", token, user.session_version, "ACTIVE")
    save_token_record(user.id, user.username, "PROOF", proof, user.session_version, "CURRENT")
    log_event(db, user.id, "LOGIN_SUCCESS",
              f"Token issued (v{user.session_version}). Proof: {proof[:20]}...")

    return {"message": "Login successful", "token": token, "user_id": user.id, "username": user.username,
            "reset_counter": user.reset_counter, "session_version": user.session_version, "current_proof": proof}


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
        save_token_record(user.id, user.username, "TOKEN", token[:60], payload["session_version"], "REJECTED")
        log_event(db, user.id, "SESSION_REJECTED",
                  f"Token v{payload['session_version']} != DB v{user.session_version}")
        raise HTTPException(status_code=401,
            detail=f"Session invalidated. Token v{payload['session_version']}, Current v{user.session_version}.")
    return {"message": f"Welcome, {user.username}!", "user_id": user.id, "username": user.username,
            "reset_counter": user.reset_counter, "session_version": user.session_version,
            "token_session_version": payload["session_version"]}


@router.post("/api/request-reset")
def request_reset(req: ResetRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="Email not found")
    lockout = check_otp_lockout(user)
    if lockout["locked"]:
        log_event(db, user.id, "RESET_BLOCKED", f"Locked. {lockout['minutes_remaining']} min remaining")
        db.commit()
        raise HTTPException(status_code=423, detail=lockout["message"])

    db.query(OTPStore).filter(OTPStore.user_id == user.id, OTPStore.is_used == False).update({"is_used": True})
    otp_code = generate_otp()
    db.add(OTPStore(user_id=user.id, otp_code=otp_code, expires_at=get_otp_expiry(), is_used=False))
    db.commit()

    proof = generate_proof(user.password_hash, user.reset_counter)
    log_event(db, user.id, "RESET_REQUESTED",
              f"OTP generated. reset_counter={user.reset_counter}. Proof: {proof[:20]}...")

    return {"message": "OTP generated", "otp": otp_code, "expires_in_seconds": 120,
            "current_proof": proof, "reset_counter": user.reset_counter,
            "otp_attempts_used": user.failed_otp_attempts, "otp_attempts_max": MAX_OTP_ATTEMPTS,
            "note": "In production, OTP sent via email/SMS."}


@router.post("/api/verify-otp")
def verify_otp(req: VerifyOTPRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    lockout = check_otp_lockout(user)
    if lockout["locked"]:
        db.commit()
        raise HTTPException(status_code=423, detail=lockout["message"])

    otp_entry = db.query(OTPStore).filter(
        OTPStore.user_id == user.id, OTPStore.is_used == False
    ).order_by(OTPStore.created_at.desc()).first()
    if not otp_entry:
        raise HTTPException(status_code=400, detail="No valid OTP. Request a new one.")

    now = datetime.now(timezone.utc)
    expires = otp_entry.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if now > expires:
        otp_entry.is_used = True
        db.commit()
        log_event(db, user.id, "OTP_EXPIRED", "OTP expired")
        raise HTTPException(status_code=400, detail="OTP expired.")

    if otp_entry.otp_code != req.otp:
        user.failed_otp_attempts += 1
        left = MAX_OTP_ATTEMPTS - user.failed_otp_attempts
        if user.failed_otp_attempts >= MAX_OTP_ATTEMPTS:
            user.otp_locked_until = datetime.now(timezone.utc) + timedelta(minutes=OTP_LOCKOUT_MINUTES)
            otp_entry.is_used = True
            db.commit()
            log_event(db, user.id, "OTP_LOCKED", f"Reset locked for {OTP_LOCKOUT_MINUTES} min")
            raise HTTPException(status_code=423, detail=f"Reset locked! Try after {OTP_LOCKOUT_MINUTES} min.")
        db.commit()
        log_event(db, user.id, "OTP_INVALID", f"Wrong OTP. {user.failed_otp_attempts}/{MAX_OTP_ATTEMPTS}")
        raise HTTPException(status_code=400, detail=f"Invalid OTP. {left} attempt(s) left.")

    if not verify_proof(req.proof, user.password_hash, user.reset_counter):
        log_event(db, user.id, "PROOF_FAILED",
                  f"Proof mismatch. Submitted: {req.proof[:20]}... Expected for rc={user.reset_counter}")
        raise HTTPException(status_code=400, detail="Proof verification failed. The cryptographic proof does not match.")

    otp_entry.is_used = True
    user.failed_otp_attempts = 0
    user.otp_locked_until = None
    db.commit()

    reset_token = create_jwt_token(user.id, user.username, user.session_version)
    log_event(db, user.id, "VERIFICATION_SUCCESS", f"OTP+Proof verified. rc={user.reset_counter}")

    return {"message": "Verification successful.", "reset_token": reset_token,
            "proof_verified": True, "otp_verified": True}


@router.post("/api/reset-password")
def reset_password(req: ResetPasswordRequest, db: Session = Depends(get_db)):
    payload = verify_jwt_token(req.reset_token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid reset token")
    user = db.query(User).filter(User.email == req.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    pwd_check = validate_password(req.new_password)
    if not pwd_check["valid"]:
        raise HTTPException(status_code=400, detail=" | ".join(pwd_check["errors"]))

    old_rc = user.reset_counter
    old_sv = user.session_version
    old_hash = user.password_hash
    old_proof = generate_proof(old_hash, old_rc)

    # Save old credentials
    save_credential_event(user.id, user.username, user.email, f"OLD_PASSWORD_RESET_{old_rc}",
                          old_hash, old_proof, old_rc, old_sv)
    save_token_record(user.id, user.username, "PROOF", old_proof, old_sv, "INVALIDATED")
    save_token_record(user.id, user.username, "TOKEN", "ALL_TOKENS_V" + str(old_sv), old_sv, "REVOKED_AT_RESET")

    # Update
    new_hash = hash_password(req.new_password)
    user.password_hash = new_hash
    user.reset_counter += 1
    user.session_version += 1
    db.commit()
    db.refresh(user)

    new_proof = generate_proof(new_hash, user.reset_counter)

    # Save new credentials
    save_credential_event(user.id, user.username, user.email, f"NEW_PASSWORD_RESET_{user.reset_counter}",
                          new_hash, new_proof, user.reset_counter, user.session_version)
    save_token_record(user.id, user.username, "PROOF", new_proof, user.session_version, "CURRENT")

    append_csv(USERS_CSV, [user.id, user.username, user.email, user.reset_counter, user.session_version,
                           f"RESET:{datetime.now(timezone.utc).isoformat()}"])

    log_event(db, user.id, "PASSWORD_RESET_COMPLETE",
              f"rc:{old_rc}->{user.reset_counter} sv:{old_sv}->{user.session_version} "
              f"OldHash:{old_hash[:20]}... NewHash:{new_hash[:20]}... "
              f"OldProof:{old_proof[:20]}... NewProof:{new_proof[:20]}...")
    log_event(db, user.id, "SESSIONS_REVOKED", f"All v{old_sv} sessions invalidated")

    return {"message": "Password reset successful.", "old_reset_counter": old_rc,
            "new_reset_counter": user.reset_counter, "old_session_version": old_sv,
            "new_session_version": user.session_version, "old_proof": old_proof,
            "new_proof": new_proof, "sessions_revoked": True}


@router.post("/api/test-replay")
def test_replay(req: ReplayTestRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    is_valid = verify_proof(req.old_proof, user.password_hash, user.reset_counter)
    expected = generate_proof(user.password_hash, user.reset_counter)
    if is_valid:
        return {"replay_blocked": False, "message": "Proof still valid (no reset since generated)",
                "current_reset_counter": user.reset_counter}
    log_event(db, user.id, "REPLAY_ATTACK_BLOCKED", f"Replay blocked! rc={user.reset_counter}")
    return {"replay_blocked": True, "message": "REPLAY ATTACK BLOCKED!",
            "submitted_proof": req.old_proof[:20] + "...", "expected_proof": expected[:20] + "...",
            "current_reset_counter": user.reset_counter,
            "reason": "reset_counter changed since proof was generated"}


@router.get("/api/security-logs")
def get_logs(db: Session = Depends(get_db)):
    logs = db.query(SecurityLog).order_by(SecurityLog.timestamp.desc()).limit(50).all()
    return {"logs": [{"id": l.id, "user_id": l.user_id, "event_type": l.event_type,
                      "details": l.details, "timestamp": str(l.timestamp)} for l in logs]}


@router.get("/api/user-state/{username}")
def get_user_state(username: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    proof = generate_proof(user.password_hash, user.reset_counter)
    return {"username": user.username, "email": user.email, "reset_counter": user.reset_counter,
            "session_version": user.session_version, "current_proof": proof, "created_at": str(user.created_at)}


# ============================================================
# DETAILED DATA ENDPOINTS (for logs page)
# ============================================================

@router.get("/api/all-users-detail")
def get_all_users_detail(db: Session = Depends(get_db)):
    """All users with password hash history from credentials CSV."""
    users = db.query(User).all()
    result = []
    for u in users:
        # Read password history from credentials CSV
        pwd_history = []
        if os.path.exists(CREDENTIALS_CSV):
            with open(CREDENTIALS_CSV, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if str(row.get('user_id', '')) == str(u.id) and 'OLD_PASSWORD' in row.get('event', ''):
                        pwd_history.append({
                            "reset_number": row.get('reset_counter', '?'),
                            "hash_preview": row.get('password_hash', '')[:25] + "...",
                            "full_hash": row.get('password_hash', ''),
                            "proof": row.get('proof', ''),
                            "event": row.get('event', '')
                        })

        lock_login = False
        if u.login_locked_until:
            lt = u.login_locked_until
            if lt.tzinfo is None:
                lt = lt.replace(tzinfo=timezone.utc)
            lock_login = datetime.now(timezone.utc) < lt

        lock_otp = False
        if u.otp_locked_until:
            ot = u.otp_locked_until
            if ot.tzinfo is None:
                ot = ot.replace(tzinfo=timezone.utc)
            lock_otp = datetime.now(timezone.utc) < ot

        result.append({
            "user_id": u.id,
            "username": u.username,
            "email": u.email,
            "current_password_hash": u.password_hash,
            "current_hash_preview": u.password_hash[:25] + "...",
            "reset_counter": u.reset_counter,
            "session_version": u.session_version,
            "password_history": pwd_history,
            "login_locked": lock_login,
            "otp_locked": lock_otp,
            "failed_login_attempts": u.failed_login_attempts,
            "failed_otp_attempts": u.failed_otp_attempts,
            "created_at": str(u.created_at)
        })

    return {"users": result}


@router.get("/api/token-history")
def get_token_history():
    """All tokens and proofs from CSV."""
    records = []
    if os.path.exists(TOKENS_CSV):
        with open(TOKENS_CSV, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                val = row.get('value', '')
                records.append({
                    "user_id": row.get('user_id', ''),
                    "username": row.get('username', ''),
                    "type": row.get('type', 'TOKEN'),
                    "value": val,
                    "preview": val[:40] + "..." if len(val) > 40 else val,
                    "session_version": row.get('session_version', ''),
                    "timestamp": row.get('issued_at', ''),
                    "status": row.get('status', 'UNKNOWN')
                })
    records.reverse()
    return {"records": records}


@router.get("/api/user-full-detail/{username}")
def get_user_full_detail(username: str, db: Session = Depends(get_db)):
    """Complete detail for one user including all history."""
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    proof = generate_proof(user.password_hash, user.reset_counter)

    pwd_history = []
    tokens = []
    proofs = []

    if os.path.exists(CREDENTIALS_CSV):
        with open(CREDENTIALS_CSV, 'r') as f:
            for row in csv.DictReader(f):
                if str(row.get('user_id', '')) == str(user.id) and 'OLD_PASSWORD' in row.get('event', ''):
                    pwd_history.append({
                        "reset_number": row.get('reset_counter', ''),
                        "full_hash": row.get('password_hash', ''),
                        "proof": row.get('proof', ''),
                        "timestamp": row.get('timestamp', '')
                    })

    if os.path.exists(TOKENS_CSV):
        with open(TOKENS_CSV, 'r') as f:
            for row in csv.DictReader(f):
                if str(row.get('user_id', '')) == str(user.id):
                    val = row.get('value', '')
                    entry = {
                        "type": row.get('type', ''),
                        "preview": val[:40] + "..." if len(val) > 40 else val,
                        "full_value": val,
                        "session_version": row.get('session_version', ''),
                        "timestamp": row.get('issued_at', ''),
                        "status": row.get('status', '')
                    }
                    if row.get('type', '') == 'TOKEN':
                        tokens.append(entry)
                    else:
                        proofs.append(entry)

    lock_login = False
    if user.login_locked_until:
        lt = user.login_locked_until
        if lt.tzinfo is None:
            lt = lt.replace(tzinfo=timezone.utc)
        lock_login = datetime.now(timezone.utc) < lt

    lock_otp = False
    if user.otp_locked_until:
        ot = user.otp_locked_until
        if ot.tzinfo is None:
            ot = ot.replace(tzinfo=timezone.utc)
        lock_otp = datetime.now(timezone.utc) < ot

    return {
        "username": user.username, "email": user.email,
        "reset_counter": user.reset_counter, "session_version": user.session_version,
        "current_password_hash": user.password_hash, "current_proof": proof,
        "login_locked": lock_login, "otp_locked": lock_otp,
        "password_history": pwd_history, "tokens": tokens, "proofs": proofs,
        "created_at": str(user.created_at)
    }


@router.get("/api/all-users")
def get_all_users(db: Session = Depends(get_db)):
    users = db.query(User).all()
    return {"total_users": len(users), "users": [
        {"user_id": u.id, "username": u.username, "email": u.email,
         "reset_counter": u.reset_counter, "session_version": u.session_version,
         "created_at": str(u.created_at)} for u in users]}


@router.get("/api/download/users-csv")
def dl_users():
    init_csv_files()
    return FileResponse(USERS_CSV, media_type="text/csv", filename="users_data.csv")

@router.get("/api/download/logs-csv")
def dl_logs():
    init_csv_files()
    return FileResponse(LOGS_CSV, media_type="text/csv", filename="security_logs.csv")

@router.get("/api/download/tokens-csv")
def dl_tokens():
    init_csv_files()
    return FileResponse(TOKENS_CSV, media_type="text/csv", filename="tokens_data.csv")

@router.get("/api/download/credentials-csv")
def dl_credentials():
    init_csv_files()
    return FileResponse(CREDENTIALS_CSV, media_type="text/csv", filename="credentials_history.csv")
