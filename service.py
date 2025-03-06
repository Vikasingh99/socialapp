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
# from service import update_user


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
        encrypted_password,
        # user.email,
        # user.description
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
 

def update_user(username: str, update_fields: dict):
    # Fetch the stored password from the database
    conn = get_db_connection()
    cursor = conn.cursor()

    # Get the existing user data
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    existing_user = cursor.fetchone()

    if not existing_user:
        raise HTTPException(status_code=404, detail="User not found")

    # Now, construct the dynamic query based on the fields that need to be updated
    update_query = "UPDATE users SET "
    update_values = []

    for field, value in update_fields.items():
        update_query += f"{field} = %s, "
        update_values.append(value)

    # Remove the trailing comma and space
    update_query = update_query.rstrip(", ")

    # Add the condition to update the specific user
    update_query += " WHERE username = %s"
    update_values.append(username)

    # Execute the query
    cursor.execute(update_query, tuple(update_values))

    conn.commit()
    cursor.close()
    conn.close()
    return True

def delete_user_from_db(username: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if the user exists and get their data
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    existing_user = cursor.fetchone()
    
    if existing_user is None:
        return False  # User does not exist
    
    cursor.execute("DELETE FROM users WHERE username = %s", (username,))
    conn.commit()
    return True  # User successfully deleted

def authenticate(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        request: Request = kwargs.get('request')
        token = request.headers.get("Authorization")
        
        if not token:
            raise HTTPException(status_code=403, detail="Authorization token is missing")

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
    
    #fetch the username from dict
    username = details.get("username")

    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor) 
    #The RealDictCursor is used to ensure that the result of the query is returned as a dictionary

    query = """SELECT id, username, fullname FROM users WHERE username = %s"""
    cursor.execute(query, (username,))

    #fetch and store the row(user_details)
    user_data = cursor.fetchone()
    if not user_data:
        return "Invalid Token"

    if "password" in user_data:
        del user_data["password"]

    return user_data
    

