from fastapi import FastAPI, Header, HTTPException, Request, status
from typing import List, Optional
from models import User, UpdateUser, LoginModel, PostIn, PostOut, CommentIn, CommentOut
from database import get_db_connection
from service import create_user, get_token, user_info_db , delete_user_from_db, authenticate, update_user, create_post_in_db, update_post_in_db, delete_post_in_db, get_posts_by_user_in_db, create_comment_in_db, update_comment_in_db, delete_comment_in_db, like_comment_in_db, unlike_comment_in_db, like_post_in_db, unlike_post_in_db, search_posts_in_db
from pydantic import ValidationError
from dotenv import load_dotenv
load_dotenv()

app = FastAPI(title="Social-App",
            description="An API to manage users activity."
              )
db_connection = get_db_connection()

#This section belongs to user

#Create user and append the user details into the database
@app.post("/user/signup", tags=['Users'])
def signup(user: User):
    try:
        if create_user(user, db_connection):
            return {"response": "user created"}
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Validation error: {str(e)}"
        )

#Create token by using username and password
@app.post("/user/login", tags=['Users'])
def login(user: LoginModel):
    jwt_token = get_token(user, db_connection)
    if jwt_token:
        return jwt_token
    else:
        return {"response": "invalid credentials"}
    

#Get the user detail with the decoded token and verify , return from db
@app.get("/user/details", tags=['Users'])
@authenticate
def get_user_detail(request: Request):
    user_details = request.state.user

    user_info = user_info_db(user_details)

    return  {"User_detail": user_info}

#Update the user details["UpdateUser"] model in the database from @authenticate
@app.put("/user/update_user", tags=['Users'])
@authenticate
def update_user_details(user: UpdateUser, request: Request):
    
    user_details = request.state.user
    if not user_details:
        raise HTTPException(status_code=403, detail="Invalid token or user not found")
    
    # Prepare the fields to be updated from the request (user)
    update_fields = {}

    # Only update fields that are not None (i.e., passed in the request)
    if user.fullname is not None:
        update_fields["fullname"] = user.fullname

    update_status = update_user(user_details["username"], update_fields)
    
    if update_status:
        return {"message": "User details updated successfully"}
    else:
        raise HTTPException(status_code=400, detail="Failed to update user details")


@app.delete("/user/del_user", tags=['Users'])
@authenticate
def delete_user(request: Request):
    
    user_details = request.state.user
     # Extract the username and password from user_details (since you decoded it)
    username = user_details["username"]  # Assuming password is encoded in the JWT (use hashed password logic if necessary)
    
    # Perform the delete operation
    delete_response = delete_user_from_db(username)
    
    if delete_response:
        return {"message": "User deleted successfully"}
    else:
        raise HTTPException(status_code=404, detail="User not found or incorrect password")
    

#This section related to post
# Create a new post
@app.post("/posts/create", tags=["Post"])
@authenticate
def create_post(request: Request, post: PostIn):
    # Get the user details from the authenticated request state
    user_details = request.state.user
    if not user_details:
        raise HTTPException(status_code=403, detail="Invalid token or user not found")

    post_data = create_post_in_db(post.description, user_details["user_id"])

    # Return the post data in the response
    return post_data

# Edit an existing post
@app.put("/posts/{post_id}", response_model=PostOut, tags=["Post"])
@authenticate
def update_post(request: Request, post: PostIn, post_id: int):
    user_details = request.state.user
    if not user_details:
        raise HTTPException(status_code=403, detail="Invalid token or user not found")

    update_data = update_post_in_db(post.description, post_id)
    
    return update_data


# Delete a post
@app.delete("/posts/{post_id}", response_model=dict, tags=["Post"])
@authenticate  # Apply the authentication decorator to check if the user is authenticated
def delete_post(request: Request, post_id: int):
    user_details = request.state.user  # Get the user from the request (stored in the state by the auth decorator)

    if not user_details:
        raise HTTPException(status_code=403, detail="Invalid token or user not found")

    user_id = user_details['user_id']  # Assuming the user details in the token contain the user_id

    # Call the service function to delete the post and pass the user_id for authorization
    result = delete_post_in_db(post_id, user_id)
    
    # Return the response returned by the service layer
    return result



# Get all posts created by the authenticated user (via JWT)
@app.get("/posts/user", response_model=List[PostOut], tags=["Post"])
@authenticate  # Apply the authentication decorator
def get_posts_by_user(request: Request):
    user_details = request.state.user  # Get user details from the JWT token

    if not user_details:
        raise HTTPException(status_code=403, detail="User not authenticated")

    user_id = user_details['user_id']  # Assuming the JWT payload contains 'user_id'

    # Call the service function to get posts by the user
    posts = get_posts_by_user_in_db(user_id)
    
    # Return the result returned by the service layer
    return posts


