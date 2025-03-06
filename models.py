from pydantic import BaseModel, EmailStr, Field
from typing import Optional

class User(BaseModel):
    id: Optional[int] = None
    username: str
    fullname: Optional[str]= None
    password: Optional[str]= None
    

class LoginModel(BaseModel):
    username: str
    password: str

class UpdateUser(BaseModel):
    # username: Optional[str]= None
    fullname: Optional[str]= None
    
