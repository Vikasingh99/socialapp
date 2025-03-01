import os
import hashlib
import jwt

from models import User


def encrypt_password(password):
    secret_key = os.getenv("SECRET_KEY")
    encrypted_password = hashlib.sha256((password+secret_key).encode('utf-8')).hexdigest()
    return encrypted_password

def verify_password(login_password, stored_password):
    secret_key = os.getenv("SECRET_KEY")
    encrypted_login_password = hashlib.sha256((login_password+secret_key).encode('utf-8')).hexdigest()
    if encrypted_login_password == stored_password:
        return True
    else:
        return False
    
def create_jwt_token(payload):
    secret_key = os.getenv("SECRET_KEY")
    del payload["password"]
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
    cursor.execute(get_query)
    db_user_data = cursor.fetchone()
    user_keys = ["id", "username", "fullname", "password"]
    user_data_dict = {}

    for i in range(len(user_keys)):
        user_data_dict[user_keys[i]] = db_user_data[i]

    if verify_password(login_password, user_data_dict["password"]):
        # create jwt toke 
        token = create_jwt_token(user_data_dict)
        return token
    else:
        return False
    
        



 



   