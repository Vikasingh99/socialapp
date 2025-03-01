from pydantic import BaseModel


class User(BaseModel):
    id: int | None = None 
    username: str
    fullname: str | None = None
    password: str | None = None