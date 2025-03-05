from fastapi import FastAPI, Header, HTTPException, Request
from service import os, jwt
from models import User, UpdateUser
from database import get_db_connection
from service import create_user, get_token, user_info_db , delete_user_from_db, authenticate, update_user

from dotenv import load_dotenv
load_dotenv()

app = FastAPI(title="Social-App",
            description="An API to manage users."
              )
db_connection = get_db_connection()


@app.post("/user/signup", tags=['Users'])
def signup(user: User):
    if create_user(user, db_connection):
        return {"response": "user created"}
    
@app.post("/user/login", tags=['Users'])
def login(user: User):
    jwt_token = get_token(user, db_connection)
    if jwt_token:
        return jwt_token
    else:
        return {"response": "invalid credentials"}
    


@app.get("/token", tags=['Generate token'])
async def get_token():
    secret_key = os.getenv("SECRET_KEY")
    # In a real-world scenario, this token would be generated after user login and validation
    payload = {"user_id": 2, "username": "abhi"}  # Sample payload
    token = jwt.encode(payload, secret_key, algorithm="HS256")
    return {"access_token": token}



@app.get("/protected", tags=['User details from Token'])
@authenticate
def user_detail(request: Request):
    user_details = request.state.user

    user_info = user_info_db(user_details)

    return  user_info



    # if not Authorization.startswith("Bearer "):
    #     raise HTTPException(status_code=400, detail="Authorization header must start with Bearer")
    # token = Authorization.split(" ")[1]
    # current_user = verify_jwt_token(token)  # Decodes the JWT and checks the user in the database
    # return {"user_details": current_user}


@app.put("/user", tags=['Users'])
@authenticate
async def update_user_details(user: UpdateUser, request: Request):
    print("Request Body:", user.dict()) 
    # token = request.headers.get("Authorization")
    # user_details = verify_jwt_token(token)  # Get token from headers and verify it
    user_details = request.state.user
    if not user_details:
        raise HTTPException(status_code=403, detail="Invalid token or user not found")
    
    update_status = update_user(user_details["username"], user_details["password"], user.username, user.fullname)
    
    if update_status:
        return {"message": "User details updated successfully"}
    else:
        raise HTTPException(status_code=400, detail="Failed to update user details")


#-----> token:- eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiJhYmhpIiwiZnVsbG5hbWUiOiJhYmhpIiwiZXhwIjoxNzQxNzE4MzMyfQ._AfPYVAIMMscrbnQQm2ewT1jDcBfq6kAUpJlKeSPWOQ

    # user_details = verify_jwt_token(request)
    # if not user_details:
    #     raise HTTPException(status_code=403, detail="Invalid token or user not found")
    

    # current_username = user_details["username"]
    # update_status = update_user(current_username, user.username, user.fullname)
    # if update_status:
    #     return {"message": "User details updated successfully"}
    # else:
    #     raise HTTPException(status_code=400, detail="Failed to update user details")


@app.delete("/user", tags=['Users'])
@authenticate
async def delete_user(request: Request):
    # user_details = verify_jwt_token(Authorization)  # Decodes the JWT and checks the user in the database
    # if not user_details:
    #     raise HTTPException(status_code=403, detail="Invalid token or user not found")
    user_details = request.state.user
     # Extract the username and password from user_details (since you decoded it)
    username = user_details["username"]
    password = user_details["password"]  # Assuming password is encoded in the JWT (use hashed password logic if necessary)
    
    # Perform the delete operation
    delete_response = delete_user_from_db(username, password)
    
    if delete_response:
        return {"message": "User deleted successfully"}
    else:
        raise HTTPException(status_code=404, detail="User not found or incorrect password")
    


   