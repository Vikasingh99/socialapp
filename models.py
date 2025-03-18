from pydantic import BaseModel
from typing import Optional
from datetime import datetime


#pydantic model for user
class User(BaseModel):
    user_id: Optional[int] = None
    username: str
    fullname: Optional[str]= None
    password: str
    

class LoginModel(BaseModel):
    username: str
    password: str

class UpdateUser(BaseModel):
    fullname: Optional[str]= None
    

# Pydantic models for Post
class PostIn(BaseModel):
    description: str

class PostOut(PostIn):
    post_id: int
    description: str
    created_at: datetime
    updated_at: datetime


# Models for Comment
class CommentIn(BaseModel):
    content: str  # Content of the comment

class CommentOut(CommentIn):
    id: int
    post_id: int
    user_id: int
    created_at: datetime
    updated_at: datetime
