from pydantic import BaseModel, Field
from typing import List, Optional


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
    id: Optional[int] = Field(default=None, primary_key=True)
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

    class Config:
        orm_mode = True
