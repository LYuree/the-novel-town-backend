from fastapi import Request, Response, status, APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
import jwt
from app.database import get_db
from typing import List, Dict, Any, Annotated
from app.models import User, Product, Cart, Order
from app.schemas import IProductItem
from pydantic import BaseModel
from sqlalchemy.orm.attributes import flag_modified
from app.auth import jwt_bearer, get_current_user, bcrypt_context, authenticate_user, create_access_token, user_dependency, verify_token, oauth2_scheme
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta
from typing import Optional
from fastapi.responses import RedirectResponse
from uuid import uuid4, UUID
# from sqlalchemy.dialects.postgresql import UUID


from email.mime.text import MIMEText 
from email.mime.image import MIMEImage 
from email.mime.application import MIMEApplication 
from email.mime.multipart import MIMEMultipart 
import smtplib 
import os

# for Render hosting environment 

# import json
# with open('/etc/secrets/secrecy.config.json', 'r') as f:
#     config = json.load(f)

# JWT_SECRET = config['JWT_SECRET']
# ALGORITHM = config['ALGORITHM']
# ACCESS_TOKEN_EXPIRE_MINUTES = config['ACCESS_TOKEN_EXPIRE_MINUTES']
# REFRESH_TOKEN_EXPIRE_DAYS = config['REFRESH_TOKEN_EXPIRE_DAYS']

# API_URL = "https://the-novel-town-backend.onrender.com"
# FRONTEND_URL = "https://comic-lair-vite-app.onrender.com"

# local debug

from app.certificates.secrecy import JWT_SECRET, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, REFRESH_TOKEN_EXPIRE_DAYS

API_URL = "http://localhost:8000"
FRONTEND_URL = "http://localhost:3000"

router = APIRouter()

# Схемы
class UserCreate(BaseModel):
    id: UUID  # Новый ID пользователя
    username: str
    email: str
    password: str
    active: bool
    role: str = 'USER'
    refresh_token: Optional[str] = None
    activation_token: Optional[str] = None


class ProductCreate(BaseModel):
    name: str
    price: int


class CartCreate(BaseModel):
    cart_id: UUID
    user_id: UUID


class CartAdd(BaseModel):
    product_id: int
    quantity: int


class CartUpdate(BaseModel):
    product_id: int
    quantity: int


class CartResponse(BaseModel):
    id: UUID
    user_id: UUID
    products: List[Dict[str, int]]  # Массив объектов {product_id, quantity}

class OrderCreate(BaseModel):
    user_id: UUID
    order_products: Dict[str, Any]

def send_activation_token(user_email: str, activation_token: str):
    smtp = smtplib.SMTP('smtp.gmail.com', 587) 
    smtp.ehlo() 
    smtp.starttls() 
    smtp.login('noreplyLibrarium@gmail.com', 'kftcxccvnoieoyjb')

    me = "noreplyLibrarium@gmail.com"

    # Create message container - the correct MIME type is multipart/alternative.
    msg = MIMEMultipart('alternative')
    msg['Subject'] = "Link"
    msg['From'] = "noreplyLibrarium@gmail.com"
    msg['To'] = user_email

    # Create the body of the message (a plain-text and an HTML version).
    text = "Hi!\nHow are you?\nHere is the link you wanted:\nhttp://www.python.org"
    html = f"""\
    <html>
    <head></head>
    <body>
        <a href="{API_URL}/activate/{activation_token}">Подтвердить e-mail</a>
    </body>
    </html>
    """

    # Record the MIME types of both parts - text/plain and text/html.
    part1 = MIMEText(text, 'plain')
    part2 = MIMEText(html, 'html')

    # Attach parts into message container.
    # According to RFC 2046, the last part of a multipart message, in this case
    # the HTML message, is best and preferred.
    msg.attach(part1)
    msg.attach(part2)

    # Send the message via local SMTP server.

    # s = smtplib.SMTP('localhost')

    # sendmail function takes 3 arguments: sender's address, recipient's address
    # and message to send - here it is sent as one string.
    smtp.sendmail(me, user_email, msg.as_string())
    smtp.quit()

# Пользователи
@router.post("/users/")
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists",
        )

    
    activation_token=str(uuid4())
    db_user = User(
        id=user.id,
        username=user.username,
        email=user.email,
        password=bcrypt_context.hash(user.password),
        active=user.active,
        role=user.role,
        refresh_token=None,
        activation_token=activation_token
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    send_activation_token(user.email, activation_token)

    return {"user created": "success"}


@router.get("/activate/{activation_token}")
def get_user(activation_token: str, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.activation_token == activation_token).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.active = True    
    flag_modified(user, "active")
    db.commit()
    db.refresh(user)
    redirect_url = f"{FRONTEND_URL}/signin"
    return RedirectResponse(redirect_url, status_code=status.HTTP_303_SEE_OTHER)

# @router.get("/get-role")
# async def get_role(request: Request, token: Annotated[str, Depends(get_token)]):
#     try:
#         payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
#         role = payload.get("role")
#         if not role:
#             raise HTTPException(status_code=403, detail="Role not found in token")
#         return {"role": role}
#     except jwt.InvalidTokenError:
#         raise HTTPException(status_code=403, detail="Invalid token")


@router.post("/logout")
async def logout(
    user: user_dependency,
    db: Session = Depends(get_db),
):  
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    # Invalidate the refresh token
    user.refresh_token = None
    db.commit()

    return {"message": "Logged out successfully"}


@router.get("/users/")
def user(user: user_dependency, db: Session = Depends(get_db)):
    if not user:
        raise HTTPException(status_code=401, detail='Authentication Failed')
    return {"User": user}

# Товары магазина
@router.post("/products/", response_model=IProductItem)
def create_product(product: IProductItem, db: Session = Depends(get_db)):
    db_product = Product(
        name=product.name,
        description=product.description,
        price=product.price,
        discount=product.discount,
        hit=product.hit,
        release_date=product.releaseDate,
        brand=product.brand,
        digital=product.digital,
        categories=product.categories,
        cover_type=product.cover_type,
        cover_image=product.cover_image,
        amount=product.amount,
        # images=[image.dict() for image in product.images],
        reviews=product.reviews,
    )
    db.add(db_product)
    db.commit()
    db.refresh(db_product)
    return db_product

@router.get("/products/")
def list_products(db: Session = Depends(get_db)):
    return db.query(Product).all()

@router.get("/products/{product_id}", response_model=IProductItem)
def get_product(product_id: int, db: Session = Depends(get_db)):
    product = db.query(Product).filter(Product.id == product_id).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    return product

# Корзина
@router.post("/carts/")
def create_cart(cart: CartCreate, db: Session = Depends(get_db)):
    """Создать пустую корзину для пользователя."""
    existing_cart = db.query(Cart).filter(Cart.user_id == cart.user_id).first()
    if existing_cart:
        raise HTTPException(status_code=400, detail="Cart for user already exists")
    new_cart = Cart(id=cart.cart_id, user_id=cart.user_id, products=[])
    db.add(new_cart)
    db.commit()
    db.refresh(new_cart)
    return new_cart

@router.post("/carts/{cart_id}/add")
def add_to_cart(cart_id: str, item: CartAdd, db: Session = Depends(get_db)):
    """Добавить продукт в корзину."""
    cart = db.query(Cart).filter(Cart.id == cart_id).first()
    if not cart:
        raise HTTPException(status_code=404, detail="Cart not found")

    # Создаем копию массива продуктов
    updated_products = cart.products.copy()

    # Проверяем, есть ли продукт уже в корзине
    for product in updated_products:
        if product["product_id"] == item.product_id:
            product["quantity"] += item.quantity  # Увеличиваем количество
            break
    else:
        # Если продукта нет, добавляем новый элемент
        updated_products.append({"product_id": item.product_id, "quantity": item.quantity})

    # Обновляем поле products в корзине
    cart.products = updated_products

    db.commit()
    db.refresh(cart)
    return cart

@router.get("/carts/{user_id}", response_model=CartResponse)
def get_cart(user_id: str, db: Session = Depends(get_db)):
    try:
        user_uuid = UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format for user_id")
    """Получить содержимое корзины пользователя."""
    cart = db.query(Cart).filter(Cart.user_id == user_uuid).first()
    if not cart:
        raise HTTPException(status_code=404, detail="Cart not found")
    return cart

@router.put("/carts/{cart_id}/update")
def update_cart(cart_id: str, item: CartUpdate, db: Session = Depends(get_db)):
    """Изменить количество продукта в корзине."""
    cart = db.query(Cart).filter(Cart.id == cart_id).first()
    if not cart:
        raise HTTPException(status_code=404, detail="Cart not found")

    # Если cart.products - строка, преобразуем в список
    import json
    if isinstance(cart.products, str):
        cart_products = json.loads(cart.products)
    else:
        cart_products = cart.products or []

    # Логика обновления количества
    product_found = False
    for product in cart_products:
        if product["product_id"] == item.product_id:
            product["quantity"] = item.quantity
            product_found = True
            break

    if not product_found:
        raise HTTPException(status_code=404, detail="Product not found in cart")

    # Сохраняем изменения обратно в cart.products
    cart.products = cart_products

    # Указываем, что поле изменено
    flag_modified(cart, "products")
    db.commit()
    db.refresh(cart)

    return cart

@router.delete("/carts/{cart_id}/delete/{product_id}")
def delete_from_cart(cart_id: str, product_id: int, db: Session = Depends(get_db)):
    """Удалить продукт из корзины."""
    cart = db.query(Cart).filter(Cart.id == cart_id).first()
    if not cart:
        raise HTTPException(status_code=404, detail="Cart not found")
    
    # Создаем обновленный список продуктов без удаляемого
    updated_products = [product for product in cart.products if product["product_id"] != product_id]

    # Если продукт для удаления не найден
    if len(updated_products) == len(cart.products):
        raise HTTPException(status_code=404, detail="Product not found in cart")

    # Явно присваиваем обновленный массив продуктов
    cart.products = updated_products

    # Сохраняем изменения в базе данных
    db.commit()
    db.refresh(cart)
    return cart


# Заказы
@router.post("/orders/")
def create_order(order: OrderCreate, db: Session = Depends(get_db)):
    db_order = Order(user_id=order.user_id, order_products=order.order_products)
    db.add(db_order)
    db.commit()
    db.refresh(db_order)
    return db_order

@router.get("/orders/{user_id}")
def get_orders(user_id: str, db: Session = Depends(get_db)):
    orders = db.query(Order).filter(Order.user_id == user_id).all()
    return orders

@router.get("/orders/", response_model=List[Dict[str, Any]])
def get_all_orders(db: Session = Depends(get_db)):
    """Получить все заказы всех пользователей."""
    orders = db.query(Order).all()
    if not orders:
        return []
    
    return [{"id": order.id, "user_id": order.user_id, "order_products": order.order_products} for order in orders]

@router.post("/users/token")
async def login_for_access_token(
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    user = await authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    elif not user.active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User email has not been verified",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(
        username=user.username,
        user_id=user.id,
        role=user.role,
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    refresh_token = create_access_token(
        username=user.username,
        user_id=user.id,
        role=user.role,
        expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
    )
    user.refresh_token = refresh_token
    db.commit()

    # Set refresh token as HttpOnly cookie WITHOUT Secure flag (for local dev HTTP)
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,  # ACTUAL TOKEN VALUE
        httponly=True,
        secure=True,  # False for HTTP (localhost)
        samesite="none",
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        path="/",
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
    }




@router.get("/verify-token")
async def verify_access_token(token: str = Depends(jwt_bearer)):
    verify_token(token=token)
    return {"message": "token is valid!"}


# @router.get("/users/refresh-token")
# async def refresh_access_token(
#     request: Request,  # To read cookie
#     db: Session = Depends(get_db),
# ):
#     print("refresh-token route activated")
#     refresh_token = request.cookies.get("refresh_token")
#     if not refresh_token:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Refresh token cookie missing",
#         )

#     try:
#         payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=[ALGORITHM])
#         user_id = payload.get("id")
#         if not user_id:
#             raise HTTPException(
#                 status_code=status.HTTP_401_UNAUTHORIZED,
#                 detail="Invalid refresh token",
#             )
#         user_id = user_id.strip()
#         print(f"Decoded user_id from refresh token: '{user_id}' (type: {type(user_id)})")
#         user = db.query(User).filter(User.id == user_id).first()
#         if not user or user.refresh_token != refresh_token:
#             raise HTTPException(
#                 status_code=status.HTTP_401_UNAUTHORIZED,
#                 detail="Invalid refresh token",
#             )

#         access_token = create_access_token(
#             username=user.username,
#             user_id=user.id,
#             role=user.role,
#             expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
#         )

#         return {
#             "access_token": access_token,
#             "token_type": "bearer",
#         }

#     except jwt.ExpiredSignatureError:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Refresh token has expired",
#         )
#     except jwt.InvalidTokenError:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Invalid refresh token",
#         )


@router.get("/users/refresh-token")
async def refresh_access_token(request: Request, db: Session = Depends(get_db)):
    print("refresh-token route activated")
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token cookie missing")

    try:
        payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=[ALGORITHM])
        user_id = payload.get("id")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid refresh token")
        user_id = user_id.strip()
        

        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            print(f"No user found with id: {user_id}")
            raise HTTPException(status_code=401, detail="Invalid refresh token")

        if user.refresh_token != refresh_token:
            print("Refresh token mismatch")
            raise HTTPException(status_code=401, detail="Invalid refresh token")

        access_token = create_access_token(
            username=user.username,
            user_id=user.id,
            role=user.role,
            expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        )

        return {"access_token": access_token, "token_type": "bearer"}

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    

# for logging out
@router.post("/users/logout-cookie")
async def logout_cookie(response: Response):
    """
    Removes the 'refresh_token' cookie from the client.
    Call this route from the frontend when the user presses 'log out'.
    """
    response.delete_cookie(
        key="refresh_token",
        path="/",            # Use the same path as the original cookie
    )
    # Optionally, for strict cache removal you could repeat with various samesite/secure values
    return {"message": "Logged out: refresh_token deleted"}
    
@router.get("/check-cookie")
async def check_cookie(request: Request):
    return {"refresh_token" : request.cookies.get("refresh_token")}
