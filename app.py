from fastapi import FastAPI, Response
import uuid

app = FastAPI()

db = {
    "alireza":{
        "role": "admin",
        "email": "alireza@mail.com",
        "password_hash": "mamad"
    },
}


session_db = {}

@app.post("/register")
async def register(response: Response, username: str, password: str, email: str):
    if not username in db.keys():
        password_hash = hash(password)
        db[username] = {
            "role": "user",
            "email": email,
            "password_hash": password_hash
        }
    else:
        return {"message": "User already exists."}
    print(db)
    return {"message": "Register successful"}

@app.post("/session_login")
async def session_login(response: Response, username: str, password: str):
    if username in db.keys():
        user = db[username]
        if user["password_hash"] == hash(password):
            session_id = str(uuid.uuid4())
            session_db[session_id] = {
                "username": username,
                "role": user["role"]
            }
            response.set_cookie(key="session_id", value=session_id, httponly=True)
    else:
        return {"message": "Login failed"}
    print(session_db)
    return {"message": "Login successful"}

