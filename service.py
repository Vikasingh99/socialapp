import os
import hashlib
from datetime import datetime, timedelta
from typing import Optional, List
import jwt
from models import User, UpdateUser, LoginModel, PostIn, PostOut, CommentIn, CommentOut
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

    payload = { "user_id": payload["user_id"], "username": payload["username"] }
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
        
    )

    insert_query = """
        INSERT INTO users (username, fullname, password)
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
    user_keys = ["user_id", "username", "fullname", "password"]
    user_data_dict = {}

    for i in range(len(user_keys)):
        user_data_dict[user_keys[i]] = db_user_data[i]

    if verify_password(login_password, user_data_dict["password"]):
        # create jwt toke 
        token = create_jwt_token(user_data_dict)
        return {"access token ": token, "token-type": "Bearer"}
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
            # print("User Details: ", request.state.user)

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

    query = """SELECT user_id, username, fullname FROM users WHERE username = %s"""
    cursor.execute(query, (username,))

    #fetch and store the row(user_details)
    user_data = cursor.fetchone()
    if not user_data:
        return "Invalid Token"

    if "password" in user_data:
        del user_data["password"]

    return user_data
    

# Create post
def create_post_in_db(description: str, user_id):
    db_conn = get_db_connection()
    cursor = db_conn.cursor()
    created_at = datetime.now()
    updated_at = created_at

    insert_query = """
        INSERT INTO posts (user_id, description, created_at, updated_at) 
        VALUES (%s, %s, %s, %s) RETURNING post_id;
    """
    cursor.execute(insert_query, (user_id, description, created_at, updated_at))
    post_id = cursor.fetchone()[0]

    db_conn.commit()
    cursor.close()
    db_conn.close()
    return {
        "post_id": post_id,
        "description": description,
        "created_at": created_at,
        "updated_at": updated_at
    }

#update the post
def update_post_in_db(description: str, post_id):
    try:
        db_conn = get_db_connection()
        cursor = db_conn.cursor()
        cursor.execute("SELECT * FROM posts WHERE post_id = %s", (post_id,))
        db_post = cursor.fetchone()

        if not db_post:
            raise HTTPException(status_code=404, detail="Post not found")

        updated_at = datetime.now()
        cursor.execute("UPDATE posts SET description = %s, updated_at = %s WHERE post_id = %s",
                    (description, updated_at, post_id))
        
        db_conn.commit()

        print(db_post)

        return {
            "post_id": post_id, 
            "description": description, 
            "created_at": db_post[3], 
            "updated_at": updated_at
            }
    except Exception as e:
        raise HTTPException(status_code = 500, detail = "Database connection error")

#delete the post
def delete_post_in_db(post_id: int, user_id: int):
    try:
        db_conn = get_db_connection()
        cursor = db_conn.cursor()
        
        # Retrieve the post from the database
        cursor.execute("SELECT * FROM posts WHERE post_id = %s", (post_id,))
        db_post = cursor.fetchone()

        if not db_post:
            raise HTTPException(status_code=404, detail="Post not found")

        # Check if the user is the owner of the post (assuming 'user_id' is a column in your post table)
        if db_post[1] != user_id:  # Assuming db_post[1] is the user_id of the post creator
            raise HTTPException(status_code=403, detail="You are not authorized to delete this post")

        # Proceed with deletion
        cursor.execute("DELETE FROM posts WHERE post_id = %s", (post_id,))
        db_conn.commit()

        return {"message": "Post deleted successfully"}
    
    # If the exception is an HTTPException (e.g., Post not found, Unauthorized), raise it
    except Exception as e:
        raise e

    # Catch other exceptions (e.g., database connection errors)
    except Exception as e:
        raise HTTPException(status_code=500, detail="Database connection error")


#get all the post done by a single user
def get_posts_by_user_in_db(user_id: int):
    try:
        db_conn = get_db_connection()
        cursor = db_conn.cursor()

        # Query to get posts by a specific user
        cursor.execute("""
            SELECT post_id, description, created_at, updated_at 
            FROM posts 
            WHERE user_id = %s
        """, (user_id,))

        posts = cursor.fetchall()

        if not posts:
            raise HTTPException(status_code=404, detail="No posts found for this user")

    # Convert result into list of dictionaries
        result = [
                {
                    "post_id": post_id, 
                    "description": description, 
                    "created_at": created_at, 
                    "updated_at": updated_at
                }
                for post_id, description, created_at, updated_at in posts
            ]
            
        return result

    except Exception as e:
        raise HTTPException(status_code=500, detail="Database connection error")
    

# Create a comment
def create_comment_in_db(post_id: int, user_id: int, content: str):
    try:
        db_conn = get_db_connection()
        cursor = db_conn.cursor()

        # Insert comment into the database
        created_at = updated_at = datetime.now()
        insert_query = """
            INSERT INTO comments (post_id, user_id, content, created_at, updated_at) 
            VALUES (%s, %s, %s, %s, %s) RETURNING comment_id;
        """
        cursor.execute(insert_query, (post_id, user_id, content, created_at, updated_at))
        comment_id = cursor.fetchone()[0]

        db_conn.commit()

        return {"comment_id": comment_id, "post_id": post_id, "content": content, "created_at": created_at}

    except Exception as e:
        raise HTTPException(status_code=500, detail="Database connection error")


#Update an existing comment
def update_comment_in_db(comment_id: int, user_id: int, post_id: int, new_content: str):
    try:
        db_conn = get_db_connection()
        cursor = db_conn.cursor()

        # Retrieve the comment from the database
        cursor.execute("SELECT * FROM comments WHERE comment_id = %s", (comment_id,))
        db_comment = cursor.fetchone()

        if not db_comment:
            raise HTTPException(status_code=404, detail="Comment not found")
        
        # Ensure that the user is the owner of the comment
        if db_comment[2] != user_id:  # Assuming db_comment[2] is the user_id of the comment creator
            raise HTTPException(status_code=403, detail="You are Not authorized to edit this comment")

        # Ensure that the comment belongs to the specified post
        if db_comment[1] != post_id:  # Assuming db_comment[1] is the post_id to which the comment belongs
            raise HTTPException(status_code=403, detail="This comment does not belong to the specified post")

        # Update the comment content
        updated_at = datetime.now()
        cursor.execute("UPDATE comments SET content = %s, updated_at = %s WHERE comment_id = %s",
                       (new_content, updated_at, comment_id))

        db_conn.commit()

        return {"id": comment_id, "content": new_content, "updated_at": updated_at}
    
    except Exception as e:
        raise e

    except Exception as e:
        raise HTTPException(status_code=500, detail="Database connection error")
    

#Delete an existing comment
def delete_comment_in_db(comment_id: int, user_id: int):
    try:
        db_conn = get_db_connection()
        cursor = db_conn.cursor()

        # Retrieve the comment from the database
        cursor.execute("SELECT * FROM comments WHERE comment_id = %s", (comment_id,))
        db_comment = cursor.fetchone()

        if not db_comment:
            raise HTTPException(status_code=404, detail="Comment not found")

        # Ensure that the user is the owner of the comment
        if db_comment[2] != user_id:  # Assuming db_comment[2] is the user_id of the comment creator
            raise HTTPException(status_code=403, detail="Not authorized to delete this comment")

        # Delete the comment
        cursor.execute("DELETE FROM comments WHERE comment_id = %s", (comment_id,))
        
        db_conn.commit()

        return {"message": "Comment deleted successfully"}

    except Exception as e:
        raise e

    except Exception as e:
        raise HTTPException(status_code=500, detail="Database connection error")
    
#likes a comment
def like_comment_in_db(comment_id: int, user_id: int):
    db_conn = get_db_connection()
    cursor = db_conn.cursor()

    # Check if the comment exists
    cursor.execute("SELECT * FROM comments WHERE comment_id = %s", (comment_id,))
    db_comment = cursor.fetchone()
    if not db_comment:
        raise HTTPException(status_code=404, detail="Comment not found")

    # Check if the user has already liked the comment
    cursor.execute("SELECT * FROM comment_likes WHERE comment_id = %s AND user_id = %s", (comment_id, user_id))
    existing_like = cursor.fetchone()

    if existing_like:
        raise HTTPException(status_code=400, detail="You have already liked this comment")

    # Insert the like into the comment_likes table
    cursor.execute("INSERT INTO comment_likes (comment_id, user_id, created_at) VALUES (%s, %s, CURRENT_TIMESTAMP)",
                   (comment_id, user_id))

    db_conn.commit()
    return {"message": "Comment liked successfully"}

#unlike the liked comment(remove your likes from a comment)
def unlike_comment_in_db(comment_id: int, user_id: int):
    db_conn = get_db_connection()
    cursor = db_conn.cursor()

    # Check if the comment exists
    cursor.execute("SELECT * FROM comments WHERE comment_id = %s", (comment_id,))
    db_comment = cursor.fetchone()
    if not db_comment:
        raise HTTPException(status_code=404, detail="Comment not found")

    # Check if the user has liked the comment
    cursor.execute("SELECT * FROM comment_likes WHERE comment_id = %s AND user_id = %s", (comment_id, user_id))
    existing_like = cursor.fetchone()

    if not existing_like:
        raise HTTPException(status_code=400, detail="You haven't liked this comment yet")

    # Remove the like from the comment_likes table
    cursor.execute("DELETE FROM comment_likes WHERE comment_id = %s AND user_id = %s", (comment_id, user_id))

    db_conn.commit()
    return {"message": "Comment unliked successfully"}

# Like a post
def like_post_in_db(post_id: int, user_id: int):
    db_conn = get_db_connection()
    cursor = db_conn.cursor()
    
    # Check if the user has already liked the post
    cursor.execute("SELECT * FROM post_likes WHERE post_id = %s AND user_id = %s", (post_id, user_id))
    existing_like = cursor.fetchone()

    if existing_like:
        raise HTTPException(status_code=400, detail="You have already liked this post.")
    
    # Insert the like into the table
    cursor.execute("INSERT INTO post_likes (post_id, user_id) VALUES (%s, %s)", (post_id, user_id))
    db_conn.commit()

    return {"message": "Post liked successfully"}

# Unlike a post
def unlike_post_in_db(post_id: int, user_id: int):
    db_conn = get_db_connection()
    cursor = db_conn.cursor()
    
    # Check if the user has liked the post
    cursor.execute("SELECT * FROM post_likes WHERE post_id = %s AND user_id = %s", (post_id, user_id))
    existing_like = cursor.fetchone()

    if not existing_like:
        raise HTTPException(status_code=400, detail="You haven't liked this post yet.")
    
    # Delete the like (unlike the post)
    cursor.execute("DELETE FROM post_likes WHERE post_id = %s AND user_id = %s", (post_id, user_id))
    db_conn.commit()

    return {"message": "Post unliked successfully"}


# Search posts by keyword (description)
def search_posts_in_db(keyword: Optional[str], page: int, page_size: int) -> List[dict]:
    db_conn = get_db_connection()
    cursor = db_conn.cursor()
    
    # Perform search query with ILIKE for case-insensitive matching
    search_query = "SELECT post_id, description, created_at, updated_at FROM posts WHERE description ILIKE %s LIMIT %s OFFSET %s"
    cursor.execute(search_query, ('%' + keyword + '%', page_size, (page - 1) * page_size))
    posts = cursor.fetchall()

    # Check if posts were found
    if not posts:
        raise HTTPException(status_code=404, detail="No posts found matching the keyword.")
    
    # Structure the result in the expected format
    result = [
        {"post_id": row[0], "description": row[1], "created_at": row[2], "updated_at": row[3]}
        for row in posts
    ]
    
    return result