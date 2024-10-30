from fastapi import FastAPI, Response, Cookie, HTTPException
from typing import Optional
import uuid, base64
import hashlib
import jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jwt.exceptions import InvalidTokenError



SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 5
REFRESH_TOKEN_EXPIRE_MINUTES = 24 * 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI()

db = {}
session_db = {}

blacklist_db = []



def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)




@app.get("/api/register")
async def register(response: Response, username: str, password: str, email: str, role: str):
    if not username in db.keys():
        password_hash = get_password_hash(password)
        db[username] = {
            "role": role,
            "email": email,
            "password_hash": password_hash
        }
    else:
        return {"message": "User already exists."}
    print(db)
    return {"message": "Register successful"}




@app.get("/api/jwt_login")
async def jwt_login(response: Response, username: str, password: str):
    if username in db.keys():
        user = db[username]
        role = user["role"]
        password_hash = user["password_hash"]
        if verify_password(password, password_hash):
            expire = datetime.now() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            payload = {
                "username": username,
                "role": role,
                "exp": expire
            }
            token = jwt.encode(payload, SECRET_KEY, ALGORITHM)

        else:
            return {"message": "Login failed"}
    else:
        return {"message": "Login failed"}
    return {"token": token}


@app.get("/api/admin-jwt")
async def admin_jwt(token: str):
    if not token:
        raise HTTPException(status_code=401, detail="Missing Cookie")
    if token in blacklist_db:
        raise HTTPException(status_code=403, detail="Blacklisted")

    try:
        payload = jwt.decode(token, SECRET_KEY, ALGORITHM)

    except Exception as e:
        raise HTTPException(status_code=403, detail=str(e))

    username = payload["username"]
    if payload["role"] == "admin":
        return {"message": f"FLAG_{username}"}
    
    raise HTTPException(status_code=403, detail=username)


@app.get("/api/blacklist-jwt")
async def blacklist_jwt(token: str):
    blacklist_db.append(token)
    
    return Response()

database = {
    
}

@app.get("/api/session_login")
async def session_login(response: Response, username: str, password: str):
    if username in db.keys():
        user = db[username]
        role = user["role"]
        if verify_password(password, user["password_hash"]):
            # session = f"{username}_{role}"
            # encoded_data = base64.b64encode(session.encode('utf-8'))
            # session_b64 = encoded_data.decode('utf-8')
            # salt = "mamadhacker"
            # hmac = hashlib.md5(session_b64.encode() + salt.encode())
            # user_info = session_b64 + "." + str(hmac.hexdigest())
            session_id = str(uuid.uuid4())
            session_db[session_id] = {
                "username": username,
                "role": user["role"]
            }
            response.set_cookie(key="sessionid", value=session_id, httponly=True)
        else:
            return {"message": "Login failed"}
    else:
        return {"message": "Login failed"}
    print(session_id)
    return {"message": "Login successful"}

@app.get("/api/cookie_login")
async def session_login(response: Response, username: str, password: str):
    if username in db.keys():
        user = db[username]
        role = user["role"]
        if verify_password(password, user["password_hash"]):
            session = f"{username}_{role}"
            encoded_data = base64.b64encode(session.encode('utf-8'))
            session_b64 = encoded_data.decode('utf-8')
            salt = "mamadhacker"
            hmac = hashlib.md5(session_b64.encode() + salt.encode())
            # hmac = hashlib.md5(session_b64.encode())
            user_info = session_b64 + "." + str(hmac.hexdigest())
            # user_info = session_b64 

            response.set_cookie(key="user_info", value=user_info, httponly=True)
        else:
            return {"message": "Login failed"}
    else:
        return {"message": "Login failed"}
    print(user_info)
    return {"message": "Login successful"}


@app.get("/api/admin-cookie")
async def admin(user_info: Optional[str] = Cookie(None)):
    if not user_info:
        raise HTTPException(status_code=401, detail="Missing Cookie")
    
    try:
        session_b64, session_b64_hash = user_info.split(".")
        salt = "mamadhacker"
        if not hashlib.md5(session_b64.encode() + salt.encode()).hexdigest() == session_b64_hash:
        # if not hashlib.md5(session_b64.encode()).hexdigest() == session_b64_hash:
            print("AAAAAAAAAAA")
            raise Exception
    except Exception:
        raise HTTPException(status_code=403, detail="Forbidden") 


    decoded_data = base64.b64decode(session_b64)
    session = decoded_data.decode('utf-8')
    print(session)
    s = session.split("_")
    if not len(s) == 2:
        raise HTTPException(status_code=403, detail="Invalid Cookie")
    username = s[0]
    role = s[1]

    if role == "admin":
        return {"message": f"FLAG_{username}"}
    
    raise HTTPException(status_code=403, detail="Forbidden")



@app.get("/api/admin-session")
async def admin(sessionid: Optional[str] = Cookie(None)):
    if not sessionid:
        raise HTTPException(status_code=401, detail="Missing Cookie")

    if not sessionid in session_db.keys():
        raise HTTPException(status_code=403, detail="Invalid Cookie")
    
    session = session_db[sessionid]
    username = session["username"]

    if not session["role"] == "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    
    return {"message": f"FLAG_{username}"}