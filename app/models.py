# models.py
from sqlalchemy import JSON, Boolean, Column, Float, Integer, String, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base


# Пользователи
class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, index=True)  # Уникальный ID пользователя
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String, nullable=False)  # Пароль пользователя
    active = Column(Boolean, default=True)  # Активность пользователя
    role = Column(String, default='USER')
    refresh_token = Column(String, nullable=True, default=None)
    activation_token=Column(String, nullable=True)


    carts = relationship("Cart", back_populates="user")
    orders = relationship("Order", back_populates="user")

# Товары магазина
class Product(Base):
    __tablename__ = "products"

    id = Column(Integer, autoincrement=True, primary_key=True, index=True)
    name = Column(String, nullable=False)
    description = Column(String, nullable=False)
    price = Column(Float, nullable=False)
    discount = Column(Float, default=0.0)
    hit = Column(Boolean, nullable=True)  # Null, если не задано
    release_date = Column(String, nullable=True)
    brand = Column(String, nullable=False)
    digital = Column(Boolean, default=False)
    categories = Column(JSON, nullable=False)  # Список строк
    cover_type = Column(String, nullable=False)
    cover_image = Column(String, nullable=False)
    amount = Column(Integer, nullable=False)
    # images = Column(JSON, nullable=True)  # Список объектов ICoverImage
    reviews = Column(JSON, nullable=True)  # Список строк

# Корзина (связь "пользователь — товар")
class Cart(Base):
    __tablename__ = "carts"

    id = Column(String, primary_key=True, index=True)  # ID корзины
    user_id = Column(String, ForeignKey("users.id"), nullable=False)  # ID пользователя
    products = Column(JSON, default=[])  # Массив объектов {product_id, quantity}

    user = relationship("User", back_populates="carts")

# Заказы (связь "пользователь — данные заказа")
class Order(Base):
    __tablename__ = "orders"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String, ForeignKey("users.id"))
    order_details = Column(String)  # Данные о заказе (можно сделать JSON-строкой)

    user = relationship("User", back_populates="orders")
