from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import json, os
from datetime import datetime, timedelta
from jose import jwt, JWTError

SECRET_KEY = "pvz-secret-key-2025"
ALGORITHM  = "HS256"
TOKEN_TTL  = 60

BASE_DIR   = os.path.dirname(__file__)
USERS_FILE = os.path.join(BASE_DIR, "users.json")
DATA_FILE  = os.path.join(BASE_DIR, "data.json")

app    = FastAPI(title="ПВЗ API")
bearer = HTTPBearer()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

def load_users():
    with open(USERS_FILE, encoding="utf-8") as f:
        return json.load(f)

def load_data():
    with open(DATA_FILE, encoding="utf-8") as f:
        return json.load(f)

def create_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + timedelta(minutes=TOKEN_TTL)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Токен недействителен")

def get_current_user(creds: HTTPAuthorizationCredentials = Depends(bearer)):
    return decode_token(creds.credentials)

class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/login")
def login(body: LoginRequest):
    users = load_users()
    user  = users.get(body.username)
    if not user or user["password"] != body.password:
        raise HTTPException(status_code=401, detail="Неверный логин или пароль")
    token = create_token({
        "sub":    body.username,
        "role":   user["role"],
        "name":   user["name"],
        "pvz":    user.get("pvz", ""),
        "region": user.get("region", ""),
    })
    return {"token": token, "role": user["role"], "name": user["name"], "pvz": user.get("pvz", "")}

@app.get("/me")
def me(user=Depends(get_current_user)):
    return user

@app.get("/data")
def get_data(user=Depends(get_current_user)):
    data = load_data()
    role = user["role"]

    if role == "analyst":
        return data

    if role == "supervisor":
        region = user.get("region", "")
        return [item for item in data if region.lower() in item.get("pvz", "").lower()]

    if role == "operator":
        pvz = user.get("pvz", "")
        return [item for item in data if item.get("pvz") == pvz]

    raise HTTPException(status_code=403, detail="Неизвестная роль")

# Раздаём статику
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")

@app.get("/")
def index():
    return FileResponse(os.path.join(BASE_DIR, "static", "index.html"))
