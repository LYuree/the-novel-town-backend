from pydantic import BaseModel, Field, field_validator
from typing import List, Optional
import json


# Запросы на создание пользователя
class CreateUserRequest(BaseModel):
    username: str
    password: str

# Токены доступа
class Token(BaseModel):
    access_token: str
    token_type: str

class ICoverImage(BaseModel):
    image: str

class CartUpdate(BaseModel):
    quantity: int



class IProductItem(BaseModel):
    id: Optional[int] = Field(default=None)
    name: str
    description: str
    price: float
    discount: float
    hit: Optional[bool] = None
    releaseDate: Optional[str] = None
    brand: str
    digital: bool
    categories: List[str]
    cover_type: Optional[str] = None
    cover_image: str
    amount: int
    # images: List[ICoverImage]
    reviews: Optional[List[str]] = None

    @field_validator("categories", pre=True)
    def parse_categories(cls, v):
        if isinstance(v, str):
            # If it's a JSON-string, parse it to a Python list
            return json.loads(v)
        return v
    
    @field_validator("reviews", pre=True)
    def parse_categories(cls, v):
        if isinstance(v, str):
            # If it's a JSON-string, parse it to a Python list
            return json.loads(v)
        return v

    class Config:
        orm_mode = True
