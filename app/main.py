from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.database import engine, Base
from app.routes import router

# Создаем таблицы
Base.metadata.create_all(bind=engine)

app = FastAPI(debug=True)

# Настройка CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["mail.ru",
                   "gmail.com",
                   "http://localhost:3000",
                   "http://127.0.0.1:3000",
                   "http://localhost",
                   "https://98vxpncx-3000.euw.devtunnels.ms",
                   "http://localhost:5173",
                   "https://the-novel-town-backend.onrender.com",
                   "https://comic-lair-vite-app.onrender.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Подключаем маршруты
app.include_router(router)
