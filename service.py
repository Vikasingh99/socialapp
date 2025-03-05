import os
import hashlib
from datetime import datetime, timedelta
import jwt
from models import User
import bcrypt
from database import get_db_connection
from functools import wraps
from fastapi import Request, HTTPException
from psycopg2.extras import RealDictCursor


def encrypt_password(password):
    secret_key = os.getenv("SECRET_KEY")
    encrypted_password = hashlib.sha256((password+secret_key).encode('utf-8')).hexdigest()
    return encrypted_password

def verify_password(login_password, stored_password):
    secret_key = os.getenv("SECRET_KEY")
    encrypted_login_password = hashlib.sha256((login_password+secret_key).encode('utf-8')).hexdigest()
    if encrypted_login_password == stored_password:
        return True
    
    return False
    
def create_jwt_token(payload):
    secret_key = os.getenv("SECRET_KEY")
    if "password" in payload:
        del payload["password"]

    payload = { "id": payload["id"], "username": payload["username"] }
    # Add expiration time to the payload (1 week from now)
    expiration_time = datetime.utcnow() + timedelta(weeks=1)
    payload["exp"] = expiration_time

    encoded_token = jwt.encode(payload, secret_key, algorithm="HS256")
    return encoded_token


def create_user(user: User, db_conn):
    cursor = db_conn.cursor()
    encrypted_password = encrypt_password(user.password)

    data_to_insert = (
        user.username,
        user.fullname,
        encrypted_password
    )

    insert_query = """
        INSERT INTO public.users (username, fullname, password)
        VALUES (%s, %s, %s);
    """
    cursor.execute(insert_query, data_to_insert)
    db_conn.commit()
    return True


def get_token(user: User, db_conn):
    cursor = db_conn.cursor()
    username = user.username
    login_password = user.password

    get_query = f"""
        SELECT * FROM public.USERS WHERE USERNAME = '{username}';
    """
    cursor.execute(get_query, (username))
    db_user_data = cursor.fetchone()
    user_keys = ["id", "username", "fullname", "password"]
    user_data_dict = {}

    for i in range(len(user_keys)):
        user_data_dict[user_keys[i]] = db_user_data[i]

    if verify_password(login_password, user_data_dict["password"]):
        # create jwt toke 
        token = create_jwt_token(user_data_dict)
        return {"access token ": token}
    else:
        return False

def verify_jwt_token(token):
    secret_key = os.getenv("SECRET_KEY")

    # Remove the 'Bearer ' prefix if it exists
    if token.startswith("Bearer "):
        token = token[7:]
    try:
        payload = jwt.decode(token, secret_key, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
 

def update_user(username: str, password: str, new_username: str, new_fullname: str):
    # Fetch the stored password from the database
    conn = get_db_connection()
    cursor = conn.cursor()

    # Get the existing user data
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    existing_user = cursor.fetchone()

    if not existing_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Verify the password
    stored_password = existing_user[3]  # password is in the 4th column
    secret_key = os.getenv("SECRET_KEY")
    encrypted_login_password = hashlib.sha256((password + secret_key).encode('utf-8')).hexdigest()

    if encrypted_login_password != stored_password:
        raise HTTPException(status_code=401, detail="Incorrect password")

    # Now, let's update the user's details (username, fullname)
    cursor.execute("""
        UPDATE users 
        SET username = %s, fullname = %s
        WHERE username = %s
    """, (new_username, new_fullname, username))
    
    conn.commit()

    cursor.close()
    conn.close()

    return True

def delete_user_from_db(username: str, password: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if the user exists and get their data
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    existing_user = cursor.fetchone()
    
    if existing_user is None:
        return False  # User does not exist
    
    # Verify the password
    stored_password = existing_user[3]  # Assuming the password is the 4th column in the DB
    
    if verify_password(password, stored_password):  # We use the verify_password function
        # If the password is correct, delete the user
        cursor.execute("DELETE FROM users WHERE username = %s", (username,))
        conn.commit()
        return True  # User successfully deleted
    else:
        return False 
    

def authenticate(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        request: Request = kwargs.get('request')
        token = request.headers.get("Authorization")
        
        if not token:
            raise HTTPException(status_code=403, detail="Authorization token is missing")
        print("Received token:", token)
        try:
            if token.startswith("Bearer "):
                token = token[7:]
            # Verify the JWT token
            payload = verify_jwt_token(token)
            # You can store user information in the request for further use
            request.state.user = payload  # Save user info in request state
        except Exception as e:
            raise HTTPException(status_code=401, detail=str(e))
        
        return func(*args, **kwargs)

    return wrapper



def user_info_db(details):
    username = details.get("username")

    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)

    query = """SELECT id, username, fullname FROM users WHERE username = %s"""
    cursor.execute(query, (username,))
    user_data = cursor.fetchone()

    if "password" in user_data:
        del user_data["password"]

    return user_data
    

