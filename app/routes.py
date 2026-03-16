from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.database import get_db
from app.models import User, OTPStore, SecurityLog
from app.security import (
    hash_password, verify_password,
    create_jwt_token, verify_jwt_token,
    generate_proof, verify_proof,
    generate_otp, get_otp_expiry
)

router = APIRouter()


# Request Models
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
    if len(req.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    new_user = User(
        username=req.username,
        email=req.email,
        password_hash=hash_password(req.password),
        reset_counter=0,
        session_version=1
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    log_event(db, new_user.id, "REGISTRATION",
              f"User '{req.username}' registered. reset_counter=0, session_version=1")

    return {
        "message": "Registration successful",
        "user_id": new_user.id,
        "username": new_user.username,
        "reset_counter": new_user.reset_counter,
        "session_version": new_user.session_version
    }


# 2. LOGIN
@router.post("/api/login")
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == req.username).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    if not verify_password(req.password, user.password_hash):
        log_event(db, user.id, "LOGIN_FAILED", f"Failed login for '{req.username}'")
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = create_jwt_token(user.id, user.username, user.session_version)
    current_proof = generate_proof(user.password_hash, user.reset_counter)

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


# 3. DASHBOARD (protected)
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


# 4. REQUEST RESET (generate OTP)
@router.post("/api/request-reset")
def request_reset(req: ResetRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="Email not found")

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
              f"OTP generated. reset_counter={user.reset_counter}")

    return {
        "message": "OTP generated successfully",
        "otp": otp_code,
        "expires_in_seconds": 120,
        "current_proof": current_proof,
        "reset_counter": user.reset_counter,
        "note": "In production, OTP would be sent via email/SMS. Displayed here for demo."
    }


# 5. VERIFY OTP + ZKP PROOF
@router.post("/api/verify-otp")
def verify_otp(req: VerifyOTPRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

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
        log_event(db, user.id, "OTP_INVALID", "Wrong OTP entered")
        raise HTTPException(status_code=400, detail="Invalid OTP code")

    # VERIFY ZKP PROOF
    if not verify_proof(req.proof, user.password_hash, user.reset_counter):
        log_event(db, user.id, "PROOF_FAILED",
                  f"ZKP proof failed for reset_counter={user.reset_counter}")
        raise HTTPException(status_code=400, detail="Proof verification failed")

    otp_entry.is_used = True
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
    if len(req.new_password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    old_rc = user.reset_counter
    old_sv = user.session_version
    old_proof = generate_proof(user.password_hash, user.reset_counter)

    # Update password and increment counters
    user.password_hash = hash_password(req.new_password)
    user.reset_counter += 1
    user.session_version += 1
    db.commit()
    db.refresh(user)

    new_proof = generate_proof(user.password_hash, user.reset_counter)

    log_event(db, user.id, "PASSWORD_RESET_COMPLETE",
              f"reset_counter: {old_rc}→{user.reset_counter}, "
              f"session_version: {old_sv}→{user.session_version}")
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


# 7. TEST REPLAY ATTACK
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
            "message": "Proof is still valid (no reset occurred since this proof was generated)",
            "current_reset_counter": user.reset_counter
        }
    else:
        log_event(db, user.id, "REPLAY_ATTACK_BLOCKED",
                  f"Replay blocked! reset_counter={user.reset_counter}")
        return {
            "replay_blocked": True,
            "message": "REPLAY ATTACK BLOCKED! The proof is no longer valid.",
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
        "current_proof": proof,
        "created_at": str(user.created_at)
    }
