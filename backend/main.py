from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import timedelta
import backend.database as database
import backend.crud as crud
import backend.schemas as schemas
import backend.auth as auth
from backend.deps import get_db, get_current_active_user, get_current_admin
from backend.capture_service import start_capture, stop_capture, is_running

app = FastAPI(title="DNS Tunneling Detection API")

# Allow CORS for Streamlit front-end
origins = ["http://localhost:8501", "http://127.0.0.1:8501"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    database.init_db()


@app.post("/register", response_model=schemas.UserOut)
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    existing = crud.get_user_by_email(db, user.email)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    new_user = crud.create_user(db, user)
    return new_user


@app.post("/login", response_model=schemas.Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = crud.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    # Use new 24h default expiry from auth.create_jwt_token
    token = auth.create_jwt_token({"sub": user.id, "role": user.role})
    return {"access_token": token, "token_type": "bearer"}


@app.post("/log_suspicious", response_model=schemas.SuspiciousOut)
def log_suspicious(item: schemas.SuspiciousCreate, current_user=Depends(get_current_active_user), db: Session = Depends(get_db)):
    created = crud.create_suspicious(db, user_id=current_user.id, item=item)
    return created


@app.get("/user/suspicious", response_model=list[schemas.SuspiciousOut])
def get_user_suspicious(current_user=Depends(get_current_active_user), db: Session = Depends(get_db)):
    return crud.get_user_suspicious(db, user_id=current_user.id)


@app.get("/admin/suspicious_all", response_model=list[schemas.SuspiciousOut])
def get_all_suspicious(admin_user=Depends(get_current_admin), db: Session = Depends(get_db)):
    return crud.get_all_suspicious(db)


@app.post("/start_capture")
def start_capture_endpoint(current_user=Depends(get_current_active_user)):
    started = start_capture(current_user.id)
    if not started:
        return {"status": "already_running"}
    return {"status": "started"}


@app.post("/stop_capture")
def stop_capture_endpoint(current_user=Depends(get_current_active_user)):
    stopped = stop_capture()
    if not stopped:
        return {"status": "not_running"}
    return {"status": "stopped"}


@app.get("/capture_status")
def capture_status():
    return {"running": is_running()}
