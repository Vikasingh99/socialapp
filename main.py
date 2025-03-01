from fastapi import FastAPI, status

from models import User
from database import get_db_connection
from service import create_user, get_token

from dotenv import load_dotenv
load_dotenv()

app = FastAPI()
db_connection = get_db_connection()



@app.post("/users/signup")
def signup(user: User):
    if create_user(user, db_connection):
        return {"response": "user created"}
    
@app.post("/users/signin")
def signin(user: User):
    jwt_token = get_token(user, db_connection)
    if jwt_token:
        return jwt_token
    else:
        return {"response": "invalid credentials"}
    

