from fastapi import FastAPI, Header, HTTPException, Request, status
from service import os, jwt
from models import User, UpdateUser, LoginModel
from database import get_db_connection
from service import create_user, get_token, user_info_db , delete_user_from_db, authenticate, update_user
from pydantic import ValidationError
from dotenv import load_dotenv
load_dotenv()

app = FastAPI(title="Social-App",
            description="An API to manage users."
              )
db_connection = get_db_connection()


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
@app.get("/user/details", tags=['User details from Token'])
@authenticate
def user_detail(request: Request):
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


@app.delete("/user/delete_user", tags=['Users'])
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
    


   