import os
import json
import logging
import secrets
import bcrypt
import jwt
import asyncio
import re
import threading
import time
from dotenv import load_dotenv
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from contextlib import contextmanager
from logger import get_logger

# === FASTAPI & PYDANTIC ===
from fastapi import FastAPI, Request, HTTPException, Form, Depends, BackgroundTasks, Cookie, Query, Response
from starlette.responses import RedirectResponse
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles 
from pydantic_settings import BaseSettings
from fastapi.concurrency import run_in_threadpool
from pydantic import Field, ValidationError, BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# === DATABASE ===
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Boolean, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy import create_engine as raw_engine, text


# === AUTHENTICATION ===
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# === GOOGLE SHEETS ===
import gspread
from oauth2client.service_account import ServiceAccountCredentials

# === LOGGING ===
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# === КОНФИГУРАЦИЯ ===
GOOGLE_CREDENTIALS_VALUE = os.getenv("GOOGLE_CREDENTIALS")


class Settings(BaseSettings):
    SECRET_KEY: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    DATABASE_URL: str = "sqlite:///./database.db"
    EXISTING_DB_PATH: str = "./articles.db"
    # Имя Google Таблицы
    GOOGLE_SPREADSHEET_NAME: str = "Заказы МЗ 0.2KRD"
    # Переменная с JSON-ключом
    GOOGLE_CREDENTIALS_JSON: str = ""

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()
# === БАЗА ДАННЫХ ===
engine = create_engine(settings.DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# === МОДЕЛИ SQLAlchemy ===
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=True)
    hashed_password = Column(String, nullable=False)
    position = Column(String, nullable=True)
    department = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class OrderQueue(Base):
    __tablename__ = "order_queue"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False)
    order_data = Column(Text, nullable=False)
    status = Column(String, default='pending')
    attempt_count = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    processed_at = Column(DateTime, nullable=True)

class Notification(Base):
    __tablename__ = "notifications"
    id = Column(Integer, primary_key=True, index=True)
    # Поля из вебхука
    sheet_name = Column(String, nullable=False)      # Имя листа (например, '7')
    row_number = Column(Integer, nullable=False)    # Номер строки
    order_number = Column(String, nullable=True)    # Номер заказа (C)
    article = Column(String, nullable=True)         # Артикул (B)
    name = Column(String, nullable=True)            # Наименование (F)
    order_id = Column(String, nullable=True)        # ID заказа / Причина / Экспо (P)
    order_date = Column(String, nullable=True)      # Дата заказа (O)
    chat_id = Column(String, nullable=True)         # ID пользователя (Q) - можно использовать для фильтрации
    action = Column(String, nullable=False)         # 'confirmed', 'rejected', 'expo_on', 'expo_off'
    message = Column(Text, nullable=False)          # Сгенерированное сообщение
    # Системные поля
    created_at = Column(DateTime, default=datetime.utcnow)
    is_read = Column(Boolean, default=False) 


class ProxiedLimiterKeyFunc:
    """
    Получает реальный IP клиента из заголовков X-Forwarded-For,
    которые передает Nginx. Если заголовка нет, берет прямой IP.
    """
    def __call__(self, request: Request) -> str:
        # Сначала проверяем заголовок от Nginx/Cloudflare
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            
            return forwarded.split(",")[0].strip()
        
        # Если заголовка нет, берем прямой IP (для локальной разработки или прямого доступа)
        if request.client:
            return request.client.host
        
        return "127.0.0.1"
        
# === ИНИЦИАЛИЗАЦИЯ БАЗЫ ===
Base.metadata.create_all(bind=engine)

# === FASTAPI ===
app = FastAPI(
    title="Кранодарский бот", 
    version="2.0.0",
    docs_url=None, 
    redoc_url=None, 
    debug=False     
)
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")
limiter = Limiter(key_func=ProxiedLimiterKeyFunc())
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
log = get_logger()
# === Классы вне логики ===
class NotificationReadRequest(BaseModel):
    notification_ids: List[int]


class OrderNotification(BaseModel):
    sheet_name: str
    row_number: int
    order_number: str
    article: str
    name: str
    order_id: str 
    order_date: str 
    chat_id: str 
    action: str 

# === ФУНКЦИИ АВТОРИЗАЦИИ ===
def verify_password(plain_password, hashed_password):
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def get_password_hash(password):
    # Увеличим rounds для большей стойкости (по умолчанию 12)
    salt = bcrypt.gensalt(rounds=14)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
        return username
    except jwt.exceptions.PyJWTError:
        return None

def get_current_user(token: str = None):
    if not token:
        return None
    
    
    username = decode_access_token(token)
    if not username:
        return None
    
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        return user
    finally:
        db.close()


# === РАБОТА С СУЩЕСТВУЮЩЕЙ БАЗОЙ (SQLAlchemy raw SQL для совместимости) ===
from sqlalchemy import create_engine as raw_engine, text

existing_db_engine = raw_engine(f"sqlite:///{settings.EXISTING_DB_PATH}")

def get_product_info_from_existing_db(article: str, shop: str) -> Optional[Dict[str, Any]]:
    full_key_exact = f"{article}{shop}"
    with existing_db_engine.connect() as conn:
        # 1. Поиск по точному ключу
        result = conn.execute(text("""
            SELECT full_key, store_number, department, article_code, name, gamma,
                   supplier_code, supplier_name, is_top_store
            FROM articles
            WHERE full_key = :full_key
        """), {"full_key": full_key_exact})
        row = result.mappings().fetchone() # <-- .mappings() гарантирует, что row - это dict-like

        if not row:
            # 2. Поиск по префиксу
            result = conn.execute(text("""
                SELECT full_key, store_number, department, article_code, name, gamma,
                       supplier_code, supplier_name, is_top_store
                FROM articles
                WHERE full_key LIKE :prefix
                ORDER BY full_key
                LIMIT 1
            """), {"prefix": f"{article}%"})
            row = result.mappings().fetchone() # <-- Также используем .mappings()

        if row:
            supplier_id = row['supplier_code']
            supplier_data = get_supplier_dates_from_existing_db(supplier_id, shop)
            order_date, delivery_date = calculate_delivery_date_from_supplier_data(supplier_data)

            return {
                'Артикул': row['article_code'],
                'Название': row['name'],
                'Отдел': row['department'],
                'Магазин': row['store_number'],
                'Поставщик': row['supplier_name'],
                'Дата заказа': order_date,
                'Дата поставки': delivery_date,
                'Номер поставщика': supplier_id,
                'Топ в магазине': str(row['is_top_store'])
            }
    return None

def get_supplier_dates_from_existing_db(supplier_id: str, shop: str) -> Dict[str, Any]:
    supplier_id = str(supplier_id).strip()
    if not supplier_id:
        return {}

    table_name = f"Даты выходов заказов {shop}"
    with existing_db_engine.connect() as conn:
        try:
            result = conn.execute(text(f"""
                SELECT "Номер осн. пост.", "Название осн. пост.", "Срок доставки в магазин",
                       "День выхода заказа", "День выхода заказа 2", "День выхода заказа 3",
                       "Каникулы список", "Исключения список"
                FROM '{table_name}'
                WHERE "Номер осн. пост." = :supplier_id
            """), {"supplier_id": supplier_id})
            row = result.mappings().fetchone()
            if row:
                return dict(row)
        except Exception:
            logger.warning(f"Таблица '{table_name}' не найдена или ошибка запроса.")
            return {}
    return {}

def calculate_delivery_date_from_supplier_data(supplier_data: Dict[str, Any]) -> tuple[str, str]:
    # Упрощённый расчет, как в старом коде
    today = datetime.now().date()
    order_date = today.strftime("%d.%m.%Y")
    delivery_days = supplier_data.get("Срок доставки в магазин", 3)
    delivery_date = (today + timedelta(days=delivery_days)).strftime("%d.%m.%Y")
    return order_date, delivery_date


# === ВОРКЕР (пока ручной запуск) ===
def process_order_queue():
    """Функция для фонового запуска (например, через Celery или cron)"""

    load_dotenv('secret.env')
    google_creds_json = os.getenv("GOOGLE_CREDENTIALS")
    db = SessionLocal()
    pending_orders = db.query(OrderQueue).filter(OrderQueue.status == 'pending').limit(5).all()

    for order_item in pending_orders:
        order_id = order_item.id
        user_id = order_item.user_id
        order_data_str = order_item.order_data  # <-- Получаем строку

        try:
            # ДЕСЕРИАЛИЗАЦИЯ
            order_data = json.loads(order_data_str) # <-- Ошибка может быть здесь, если строка испорчена
            logger.info(f"Обработка заказа {order_id}: {order_data}")

            # Тут твой код из воркера
            # 1. Подключаемся к Google Sheets
            scope = ['https://spreadsheets.google.com/feeds', 'https://www.googleapis.com/auth/drive']
            
            if not google_creds_json:
                raise EnvironmentError("Переменная окружения GOOGLE_CREDENTIALS не найдена")

            creds_dict = json.loads(google_creds_json)
            creds = ServiceAccountCredentials.from_json_keyfile_dict(creds_dict, scope)
            client = gspread.authorize(creds)
            spreadsheet = client.open(settings.GOOGLE_SPREADSHEET_NAME)

            # --- ПРОВЕРКА ИМЕНИ ЛИСТА ---
            dept = order_data['department']
            logger.info(f"Поиск листа с именем: '{dept}'")
            worksheet = spreadsheet.worksheet(dept) # <-- Ошибка может быть здесь, если лист не найден
            logger.info(f"Лист найден: {worksheet.title}")

            # 2. Находим следующую строку
            next_row = len(worksheet.col_values(1)) + 1
            logger.info(f"Следующая строка для записи: {next_row}")

            # 3. Формируем обновления (как в твоём коде)
            updates = [
                {'range': f'A{next_row}', 'values': [[order_data['selected_shop']]]},
                {'range': f'B{next_row}', 'values': [[int(order_data['article'])]]},
                {'range': f'C{next_row}', 'values': [[order_data['order_reason']]]},
                {'range': f'D{next_row}', 'values': [[datetime.now().strftime("%d.%m.%Y %H:%M")]]},
                {'range': f'E{next_row}', 'values': [[f"{order_data['user_name']}, {order_data['user_position']}"]]},
                {'range': f'K{next_row}', 'values': [[int(order_data['quantity'])]]},
                {'range': f'R{next_row}', 'values': [[user_id]]}
            ]

            # --- ПРОВЕРКА ОБНОВЛЕНИЯ ---
            logger.info(f"WORKER: Writing order {order_id} to sheet '{dept}'")
            result_of_update = worksheet.batch_update(updates) # <-- ОШИБКА ВОЗНИКАЕТ ЗДЕСЬ
            logger.info(f"Результат batch_update: {result_of_update}") # <-- Вот тут может быть пусто

            # 4. Обновляем статус
            order_item.status = 'completed'
            order_item.processed_at = datetime.utcnow()
            db.commit()
            log.info(f"WORKER SUCCESS: Order {order_id} written to Google Sheet '{dept}' by user {order_data.get('user_name')}")

        except json.JSONDecodeError as je:
            logger.error(f"Ошибка декодирования JSON в заказе {order_id}: {je}. Данные: {order_data_str}")
            order_item.status = 'failed'
            order_item.error_message = f"JSONDecodeError: {str(je)}"
            order_item.attempt_count += 1
            db.commit()

        except gspread.WorksheetNotFound as we:
            logger.error(f"Лист '{dept}' не найден в таблице '{settings.GOOGLE_SPREADSHEET_NAME}'. Заказ {order_id}. {we}")
            order_item.status = 'failed'
            order_item.error_message = f"WorksheetNotFound: {str(we)}"
            order_item.attempt_count += 1
            db.commit()

        except gspread.GSpreadException as ge:
            # Любая ошибка gspread, включая ошибки API
            logger.error(f"gspread ошибка при обработке заказа {order_id}: {ge}")
            order_item.status = 'failed'
            order_item.error_message = f"gspread error: {str(ge)}"
            order_item.attempt_count += 1
            db.commit()

        except Exception as e:
            # Любая другая ошибка
            logger.error(f"Неизвестная ошибка при обработке заказа {order_id}: {e}")
            order_item.status = 'failed'
            order_item.error_message = str(e)
            order_item.attempt_count += 1
            db.commit()

    db.close()

# === МАРШРУТЫ ===

# --- Главная страница ---
@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    token = request.cookies.get("access_token")
    user = get_current_user(token)
    if not user:
        return RedirectResponse(url="/login")
    return RedirectResponse(url="/app")

@app.get("/app", response_class=HTMLResponse)
async def app_ui(request: Request):
    token = request.cookies.get("access_token")
    user = get_current_user(token)
    if not user:
        return RedirectResponse(url="/login")
    return templates.TemplateResponse("app.html", {
        "request": request,
        "user": {
            "username": user.username,
            "position": user.position or "без должности"
        }
    })

@app.get("/login", response_class=HTMLResponse)
async def get_login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
@limiter.limit("5/5minute")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    # 1. Подготовка (синхронно)
    client_host = request.client.host if request.client else "unknown"
    
    # 2. Запрос к БД (выносим в поток)
    # Создаем отдельную функцию для логики БД, чтобы запустить её в потоке
    def verify_db_user():
        db = SessionLocal()
        try:
            user = db.query(User).filter(User.username == username).first()
            return user
        finally:
            db.close()

    user = await run_in_threadpool(verify_db_user)

    if not user:
        log.warning(f"LOGIN FAILED: User='{username}', IP={client_host}")
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Неверные учетные данные"
        })

    # 3. Проверка пароля (bcrypt — ОЧЕНЬ тяжелая операция, обязательно в поток!)
    is_password_valid = await run_in_threadpool(verify_password, password, user.hashed_password)

    if not is_password_valid:
        log.warning(f"LOGIN FAILED (Wrong Pass): User='{username}', IP={client_host}")
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Неверные учетные данные"
        })

    # 4. Успех
    log.info(f"LOGIN SUCCESS: User='{username}', IP={client_host}")
    
    token_data = {"sub": user.username}
    token = create_access_token(data=token_data)

    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=1800
    )
    return response
    

@app.get("/logout")
async def logout(response: RedirectResponse):
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(key="access_token")
    return response
    

@app.get("/register", response_class=HTMLResponse)
async def get_register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})
    

@app.get("/notifications", response_class=HTMLResponse)
async def show_notifications(request: Request, access_token: str = Cookie(None)):
    user = get_current_user(access_token)
    if not user:
        return RedirectResponse(url="/login")
    return templates.TemplateResponse("notifications.html", {"request": request, "user": {"username": user.username}})


@app.post("/register")
async def register(
    request: Request, 
    username: str = Form(...), 
    password: str = Form(...), 
    position: str = Form("")
):
    # Валидация (синхронно, быстро)
    if username.isdigit():
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Логин не может состоять только из цифр."
        })
    if not re.match(r'^[A-Za-z_]+$', username):
         return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Только латинские буквы."
        })
    if len(password) < 6:
         return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Пароль слишком короткий."
        })

    # Логика БД и хеширования (выносим в отдельную функцию)
    def process_registration():
        db = SessionLocal()
        try:
            existing_user = db.query(User).filter(User.username == username).first()
            if existing_user:
                return "exists"
            
            # Хеширование (тяжело!)
            hashed_pw = get_password_hash(password)
            
            new_user = User(username=username, hashed_password=hashed_pw, position=position)
            db.add(new_user)
            db.commit()
            return "ok"
        except Exception as e:
            log.error(f"Registration error: {e}")
            return "error"
        finally:
            db.close()

    # Запускаем в потоке
    result = await run_in_threadpool(process_registration)

    if result == "exists":
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Пользователь уже существует"
        })
    
    return RedirectResponse(url="/login", status_code=303)

# --- API: Поиск товара (с токеном из заголовка) ---
security = HTTPBearer()

@app.post("/api/search")
async def search_article(
    request: Request,
    access_token: str = Cookie(None),
    article: str = Form(...),
    shop: str = Form(...)
):
    user = get_current_user(access_token)
    if not user:
        raise HTTPException(status_code=401, detail="Не авторизован")

    if not article or not shop:
        raise HTTPException(status_code=400, detail="Артикул и магазин обязательны")

    
    product_info = await run_in_threadpool(get_product_info_from_existing_db, article, shop)
    
    if product_info:
        return {"found": True, "data": product_info}
    return {"found": False, "message": f"Артикул {article} не найден для магазина {shop}"}


# --- API: Создание заказа (с токеном из заголовка) ---
@app.post("/api/order")
async def create_order(
    request: Request, # <- Добавляем Request
    access_token: str = Cookie(None), # <- Получаем токен из куки
    article: str = Form(...),
    shop: str = Form(...),
    department: str = Form(...),
    quantity: int = Form(...),
    order_reason: str = Form(...)
):
    user = get_current_user(access_token) # <- Передаём токен из куки
    if not user:
        raise HTTPException(status_code=401, detail="Не авторизован")

    try:
        quantity = int(quantity)
    except ValueError:
        raise HTTPException(status_code=400, detail="Количество должно быть числом")

    order_data = {
        "selected_shop": shop,
        "article": article,
        "order_reason": order_reason,
        "department": department,
        "quantity": quantity,
        "user_name": user.username,
        "user_position": user.position or "сотрудник",
        "user_id": user.id
    }
    log.info(f"ORDER CREATED: User='{user.username}', Article={article}, Shop={shop}, Qty={quantity}, Reason='{order_reason}'")
    

    db = SessionLocal()
    queue_entry = OrderQueue(
        user_id=user.id,
        order_data=json.dumps(order_data, ensure_ascii=False)
    )
    db.add(queue_entry)
    db.commit()
    db.refresh(queue_entry)
    db.close()

    return {"status": "queued", "queue_id": queue_entry.id}

@app.get("/api/notifications")
async def get_notifications(
    limit: int = Query(20, ge=0, le=100),
    offset: int = Query(0, ge=0),
    unread_only: bool = Query(False),
    access_token: str = Cookie(None)
):
    user = get_current_user(access_token)
    if not user:
        raise HTTPException(status_code=401, detail="Не авторизован")

    # Функция работы с БД
    def fetch_notifications():
        db = SessionLocal()
        try:
            query = db.query(Notification).filter(Notification.chat_id == str(user.id))
            if unread_only:
                query = query.filter(Notification.is_read == False)
            
            query = query.order_by(Notification.created_at.desc())
            notifications = query.offset(offset).limit(limit).all()
            
            result = []
            for n in notifications:
                result.append({
                    "id": n.id,
                    "sheet_name": n.sheet_name,
                    "row_number": n.row_number,
                    "order_number": n.order_number,
                    "article": n.article,
                    "name": n.name,
                    "order_id": n.order_id,
                    "order_date": n.order_date,
                    "chat_id": n.chat_id,
                    "action": n.action,
                    "message": n.message,
                    "created_at": n.created_at.isoformat(),
                    "is_read": n.is_read
                })
            
            total_count = db.query(Notification).filter(Notification.chat_id == str(user.id)).count()
            return {"notifications": result, "total_count": total_count}
        finally:
            db.close()

    return await run_in_threadpool(fetch_notifications)

# --- API: Отметить уведомления как прочитанные ---
@app.post("/api/notifications/read")
async def mark_notifications_read(
    request: NotificationReadRequest,  # <--- Принимаем модель, а не "голый" список
    access_token: str = Cookie(None)
):
    user = get_current_user(access_token)
    if not user:
        raise HTTPException(status_code=401, detail="Не авторизован")

    # 2. Достаем список ID из модели
    notification_ids = request.notification_ids

    if not notification_ids:
        return {"status": "nothing_to_update"}

    db = SessionLocal()
    try:
        rows_updated = db.query(Notification).filter(
            Notification.id.in_(notification_ids)
        ).update({"is_read": True}, synchronize_session=False)
        db.commit()
        return {"status": "ok", "updated_count": rows_updated}
    except Exception as e:
        db.rollback()
        logger.error(f"Ошибка обновления статуса уведомлений: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        db.close()


# --- Уведомления ---
class OrderNotification(BaseModel):
    sheet_name: str
    row_number: int
    order_number: str
    article: str
    name: str
    order_id: str
    order_date: str
    chat_id: str # или int, в зависимости от того, как ты хранишь

# --- ФУНКЦИИ ДЛЯ ОПРЕДЕЛЕНИЯ ТИПА УВЕДОМЛЕНИЯ ---
def determine_action(notification: OrderNotification) -> str:
    order_id_str = str(notification.order_id).lower().strip()
    order_number_str = str(notification.order_number).lower().strip()

    rejection_keywords = ['отказ', 'нет', 'не буду', 'отклон', 'отмен', 'не подтверждаю']
    expo_keywords = {
        'on': ['поставить на экспо', 'на экспо'],
        'off': ['снять с экспо']
    }

    if any(keyword in order_id_str for keyword in rejection_keywords):
        return 'rejected'
    elif any(keyword in order_number_str for keyword in expo_keywords['on']):
        return 'expo_on'
    elif any(keyword in order_number_str for keyword in expo_keywords['off']):
        return 'expo_off'
    else:
        return 'confirmed'

# --- ФУНКЦИИ ДЛЯ ГЕНЕРАЦИИ СООБЩЕНИЯ ---
def generate_notification_message(notification: OrderNotification, action: str) -> str:
    article = notification.article
    name = notification.name
    order_num = notification.order_number

    if action == 'expo_on':
        return f"📦 Артикул: {article}\n🏷️ Наименование: {name}\n✅ Поставлено на экспозицию"
    elif action == 'expo_off':
        return f"📦 Артикул: {article}\n🏷️ Наименование: {name}\n❌ Снято с экспозиции"
    elif action == 'rejected':
        reason = notification.order_id
        return f"❌ Ваш заказ {order_num} не может быть выполнен.\n📦 Артикул: {article}\n🏷️ Наименование: {name}\n💬 Причина: {reason}"
    else: # confirmed
        comment = notification.order_id
        return f"✅ Ваш заказ №{order_num} оформлен!\n📦 Артикул: {article}\n🏷️ Наименование: {name}\n🔢 Комментарий: {comment or '—'}"

# --- ЭНДПОИНТ ВЕБХУКА ---
@app.post("/webhook/orders")
async def webhook_orders(request: Request):
    """
    Вебхук для получения уведомлений из Google Apps Script.
    Ожидает JSON с информацией о заказе и действии.
    """
    try:
        payload = await request.json()
        logger.info(f"Получено уведомление: {payload}")

        notification_data = OrderNotification.model_validate(payload)

        # Определяем тип действия
        action = determine_action(notification_data)

        # Генерируем сообщение
        message = generate_notification_message(notification_data, action)

        # --- СОХРАНЕНИЕ В БАЗУ ---
        db = SessionLocal()
        new_notification = Notification(
            sheet_name=notification_data.sheet_name,
            row_number=notification_data.row_number,
            order_number=notification_data.order_number,
            article=notification_data.article,
            name=notification_data.name,
            order_id=notification_data.order_id,
            order_date=notification_data.order_date,
            chat_id=notification_data.chat_id, # Можно хранить ID пользователя, если привязка нужна
            action=action,
            message=message
        )
        db.add(new_notification)
        db.commit()
        db.refresh(new_notification)
        db.close()

        logger.info(f"Уведомление сохранено в базу: {new_notification.id}")

        return {"status": "ok", "processed": True, "notification_id": new_notification.id}

    except json.JSONDecodeError:
        logger.error("Неверный JSON в теле запроса")
        raise HTTPException(status_code=400, detail="Invalid JSON")
    except ValidationError as ve:
        logger.error(f"Ошибка валидации: {ve}")
        raise HTTPException(status_code=400, detail="Validation error")
    except Exception as e:
        logger.error(f"Ошибка обработки вебхука: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

# --- START/SHUTDOWN EVENTS ---

def scheduler_loop():
    """
    Фоновый поток-демон.
    Запускается один раз при старте сервера и работает вечно.
    """
    log.info("🚀 Background Worker started. Interval: 120 sec.")
    while True:
        try:
            # Запускаем задачу обработки заказов
            process_order_queue()
        except Exception as e:
            log.error(f"🔥 Critical error in background worker: {e}")
        
        # Спим 120 секунд перед следующим запуском
        time.sleep(120)


@app.on_event("startup")
async def startup_event():

    thread = threading.Thread(target=scheduler_loop, daemon=True)
    thread.start()
    log.info("Server started. Background worker thread initiated.")
