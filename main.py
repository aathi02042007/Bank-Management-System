from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import Optional
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
import hashlib
import mysql.connector

secret = "bank_project"
logic  = "HS256"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


def create_access_token(data: dict):
    encode = data.copy()
    expire    = datetime.now() + timedelta(hours=1)
    encode.update({"exp": expire})
    token = jwt.encode(encode, secret, algorithm=logic)
    return token

def get_db():
    return mysql.connector.connect(
        host     = "localhost",
        user     = "root",
        password = "0204",
        database = "veb_box",
        port     = "3306"
    )

app = FastAPI()
#for front end link
app.add_middleware(
    CORSMiddleware,
    allow_origins     = ["*"],
    allow_credentials = True,
    allow_methods     = ["*"],
    allow_headers     = ["*"],
)

def decode_token(token: str):
    try:
        return jwt.decode(token, secret, algorithms=[logic])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

#Admin token verify panna
def verify_admin(token: str):

    data = decode_token(token)
    if data.get("role") != "admin":
        raise HTTPException(
            status_code=403,
            detail="Admin access required"
        )
    return data

@app.get("/")
def home():
    return {"message": "Apex Bank API is running"}

@app.get("/profile")
def profile(token: str = Depends(oauth2_scheme)):
    data = decode_token(token)
    return {"message": "Valid user", "data": data}

class Login(BaseModel):
    account_number: int
    password: str

class Adminlogin(BaseModel):
    username: str
    password: str

@app.post("/admin-login")
def admin_login(admin: Adminlogin):

    if admin.username != "aathi":
        return {"error": "Invalid admin username"}

    if admin.password != "0204":
        return {"error": "Invalid admin password"}

    token = create_access_token({
        "name": "Aathithyan",
        "role": "admin"
    })

    return {
        "message": "Admin login successful",
        "access_token": token
    }

@app.post("/login")
def login_user(log: Login):
    db     = get_db()
    cursor = db.cursor(dictionary=True)

    try:
        cursor.execute(
            "select * from users where account_number=%s",(log.account_number,))
        user = cursor.fetchone()

        if user is None:
            return {"error": "Account not found"}

        hashed_password = hashlib.sha256(
            log.password.encode()
        ).hexdigest()

        if hashed_password != user["password"]:
            return {"error": "Invalid password"}

        token = create_access_token({
            "account_number": user["account_number"],
            "name": user["name"],
            "role": "user"
        })
        return {
            "message":      "Login successful",
            "access_token": token,
            "token_type":   "bearer"
        }
    finally:
        cursor.close()
        db.close()

class User(BaseModel):
    name:           str
    email:          str
    password:       str
    account_number: int
    balance:        float
    created_at:     Optional[datetime] = None

@app.get("/users")
def view_user(token: str = Depends(oauth2_scheme)):

    verify_admin(token)

    db = get_db()
    cursor = db.cursor(dictionary=True)

    try:
        cursor.execute(
            "select name, email, account_number, balance, created_at from users"
        )
        return cursor.fetchall()

    finally:
        cursor.close()
        db.close()

@app.post("/users")
def create_user(detail: User):
    db     = get_db()
    cursor = db.cursor()

    try:
        cursor.execute(
            "select account_number from users where account_number=%s",(detail.account_number,))
        if cursor.fetchone():
            return {"error": "Account number already exists"}

        cursor.execute(
            "select email from users where email=%s",(detail.email,))
        if cursor.fetchone():
            return {"error": "Email already exists"}

        hashed_password = hashlib.sha256(detail.password.encode()).hexdigest()

        if detail.created_at:
            query  = """insert into users (name, email, password, account_number, balance, created_at)
                     values (%s, %s, %s, %s, %s, %s)"""
            values = (detail.name, detail.email, hashed_password,
                      detail.account_number, detail.balance, detail.created_at)
        else:
            query  = """insert into users (name, email, password, account_number, balance)
                     values (%s, %s, %s, %s, %s)"""
            values = (detail.name, detail.email, hashed_password,
                      detail.account_number, detail.balance)
        cursor.execute(query, values)
        db.commit()
        return {"message": "Account successfully created"}
    finally:
        cursor.close()
        db.close()

class Payment(BaseModel):
    sender_id:        int
    receiver_id:      int
    amount:           float
    transaction_type: str
    timestamp:        Optional[datetime] = None

@app.get("/transactions")
def view_transactions(token: str = Depends(oauth2_scheme)):

    verify_admin(token)
    db = get_db()
    cursor = db.cursor(dictionary=True)

    try:
        cursor.execute("select * from transactions")
        return cursor.fetchall()

    finally:
        cursor.close()
        db.close()

@app.get("/transactions/{account_number}")
def check_transaction(account_number: int, token: str = Depends(oauth2_scheme)):
    data = decode_token(token)
    if data["account_number"] != account_number:
        return {"error": "Unauthorized account access"}

    db     = get_db()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute(
            "select * from transactions where sender_id=%s OR receiver_id=%s",(account_number, account_number))
        transactions = cursor.fetchall()
        if not transactions:
            return {"error": "No transactions found"}
        return {"account_number": account_number, "transactions": transactions}
    finally:
        cursor.close()
        db.close()

@app.post("/transactions")
def create_transaction(tranc: Payment, token: str = Depends(oauth2_scheme)):
    data = decode_token(token)
    if data["account_number"] != tranc.sender_id:
        return {"error": "Unauthorized account access"}
    if tranc.amount <= 0:
        return {"error": "Invalid amount"}
    if tranc.sender_id == tranc.receiver_id:
        return {"error": "Cannot transfer to same account"}

    db     = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("select balance from users where account_number=%s", (tranc.sender_id,))
        sender = cursor.fetchone()
        cursor.execute("select balance from users where account_number=%s", (tranc.receiver_id,))
        receiver = cursor.fetchone()

        if sender is None:
            return {"error": "Sender account not found"}
        if receiver is None:
            return {"error": "Receiver account not found"}
        if sender[0] < tranc.amount:
            return {"error": "Insufficient balance"}

        sender_balance = sender[0]-tranc.amount
        receiver_balance = receiver[0]+tranc.amount

        cursor.execute("update users set balance=%s where account_number=%s",(sender_balance, tranc.sender_id))
        cursor.execute("update users set balance=%s where account_number=%s",(receiver_balance, tranc.receiver_id))
        cursor.execute("""insert into transactions(sender_id, receiver_id, amount, transaction_type, old_balance, new_balance, timestamp)
                                values (%s, %s, %s, %s, %s, %s, coalesce(%s, current_timestamp))""",
                       (tranc.sender_id, tranc.receiver_id, tranc.amount,tranc.transaction_type,sender[0],
                        sender_balance, tranc.timestamp))
        db.commit()
        return {"message": "Transfer completed successfully"}
    finally:
        cursor.close()
        db.close()

class Deposit(BaseModel):
    account_number: int
    amount:         float
    timestamp:      Optional[datetime] = None

@app.post("/deposit")
def deposit_money(dep: Deposit, token: str = Depends(oauth2_scheme)):
    data = decode_token(token)
    if data["account_number"] != dep.account_number:
        return {"error": "Unauthorized account access"}
    if dep.amount <= 0:
        return {"error": "Invalid amount"}

    db     = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("select balance from users where account_number=%s",(dep.account_number,))
        user = cursor.fetchone()
        if user is None:
            return {"error": "Account not found"}

        new_balance = user[0]+dep.amount
        cursor.execute("update users set balance=%s where account_number=%s",(new_balance, dep.account_number))
        cursor.execute("""insert into transactions(sender_id, receiver_id, amount, transaction_type,
                      old_balance, new_balance, timestamp)values (%s, %s, %s, %s, %s, %s, coalesce(%s, current_timestamp))""",
                       (dep.account_number, None, dep.amount,"deposit", user[0], new_balance, dep.timestamp))
        db.commit()
        return {"message": "Deposit successful"}
    finally:
        cursor.close()
        db.close()

class Withdraw(BaseModel):
    account_number: int
    amount:         float
    timestamp:      Optional[datetime] = None

@app.post("/withdraw")
def withdraw_money(withd: Withdraw, token: str = Depends(oauth2_scheme)):
    data = decode_token(token)
    if data["account_number"] != withd.account_number:
        return {"error": "Unauthorized account access"}
    if withd.amount <= 0:
        return {"error": "Invalid amount"}

    db     = get_db()
    cursor = db.cursor()
    try:
        cursor.execute(
            "select balance from users where account_number=%s",(withd.account_number,))
        user = cursor.fetchone()
        if user is None:
            return {"error": "Account not found"}
        if user[0] - withd.amount < 1000:
            return {
                "error":           "Insufficient balance. Minimum reserve of 1,000 must be maintained.",
                "current_balance": user[0]
            }
        new_balance = user[0] - withd.amount
        cursor.execute("update users set balance=%s where account_number=%s",(new_balance, withd.account_number))
        cursor.execute("""insert into transactions(sender_id, receiver_id, amount, transaction_type,
                       old_balance, new_balance, timestamp)values (%s, %s, %s, %s, %s, %s, coalesce(%s, current_timestamp))""",
                       (withd.account_number, None, withd.amount,"withdraw", user[0], new_balance, withd.timestamp))
        db.commit()
        return {"message": "Withdrawal successful"}
    finally:
        cursor.close()
        db.close()

@app.get("/balance/{account_number}")
def check_balance(account_number: int, token: str = Depends(oauth2_scheme)):
    data = decode_token(token)
    if data["account_number"] != account_number:
        return {"error": "Unauthorized account access"}

    db     = get_db()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("select balance from users where account_number=%s",(account_number,))
        user = cursor.fetchone()
        if user is None:
            return {"error": "Account not found"}
        return {"account_number": account_number, "balance": user["balance"]}
    finally:
        cursor.close()
        db.close()

class Update_User(BaseModel):
    name:     Optional[str] = None
    email:    Optional[str] = None
    password: Optional[str] = None

@app.put("/user/{account_number}")
def update_user(account_number: int, details: Update_User, token: str = Depends(oauth2_scheme)):
    data = decode_token(token)
    if data["account_number"] != account_number:
        return {"error": "Unauthorized account access"}

    db     = get_db()
    cursor = db.cursor(dictionary=True)
    updated_user = {}
    try:
        if details.name:
            cursor.execute("update users set name=%s where account_number=%s",(details.name, account_number))
            updated_user["name"] = details.name

        if details.email:
            cursor.execute("update users set email=%s where account_number=%s",(details.email, account_number))
            updated_user["email"] = details.email

        if details.password:
            hashed = hashlib.sha256(
                details.password.encode()
            ).hexdigest()

            cursor.execute("update users set password=%s where account_number=%s",(hashed, account_number))
            updated_user["password"] = "password updated"

        db.commit()
        return {"message": "Profile updated successfully", "updated_details": updated_user}
    finally:
        cursor.close()
        db.close()

class UpdateRequest(BaseModel):
    account_number: int
    new_name:       Optional[str] = None
    new_email:      Optional[str] = None
    new_password:   Optional[str] = None

@app.post("/update-request")
def create_update_request(req: UpdateRequest):
    if not any([req.new_name, req.new_email, req.new_password]):
        return {"error": "At least one field must be provided to update"}

    db     = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("""insert into update_requests (account_number, new_name, new_email, new_password)
                      values (%s, %s, %s, %s)""",
                      (req.account_number, req.new_name, req.new_email, req.new_password))
        db.commit()
        return {"message": "Update request submitted for admin approval"}
    finally:
        cursor.close()
        db.close()

@app.get("/pending-requests")
def pending_requests(token: str = Depends(oauth2_scheme)):

    verify_admin(token)

    db = get_db()
    cursor = db.cursor(dictionary=True)

    try:

        cursor.execute("select * from update_requests where status='pending' order by id DESC")
        return cursor.fetchall()

    finally:
        cursor.close()
        db.close()

@app.put("/approve-request/{request_id}")
def approve_request(
    request_id: int,
    token: str = Depends(oauth2_scheme)
):

    verify_admin(token)
    db     = get_db()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("select * from update_requests where id=%s",(request_id,))
        req = cursor.fetchone()

        if req is None:
            return {"error": "Request not found"}
        if req["status"] != "pending":
            return {"error": "Only pending requests can be approved"}

        if req["new_name"]:
            cursor.execute("update users set name=%s where account_number=%s",(req["new_name"], req["account_number"]))

        if req["new_email"]:
            cursor.execute("update users set email=%s where account_number=%s",(req["new_email"], req["account_number"]))

        if req["new_password"]:
            hashed_password = hashlib.sha256(
                req["new_password"].encode()
            ).hexdigest()

            cursor.execute("update users set password=%s where account_number=%s",(hashed_password, req["account_number"]))

        cursor.execute("update update_requests set status='approved' where id=%s",(request_id,))
        db.commit()
        return {"message": "Request approved and profile updated successfully"}
    finally:
        cursor.close()
        db.close()

@app.put("/reject-request/{request_id}")

def reject_request(request_id: int,
    token: str = Depends(oauth2_scheme)):

    verify_admin(token)
    db     = get_db()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("select * from update_requests where id=%s",(request_id,))
        req = cursor.fetchone()

        if req is None:
            return {"error": "Request not found"}
        if req["status"] != "pending":
            return {"error": "Only pending requests can be rejected"}

        cursor.execute("update update_requests set status='rejected' where id=%s",(request_id,))
        db.commit()
        return {"message": "Request rejected successfully"}
    finally:
        cursor.close()
        db.close()
