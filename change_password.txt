import sys
import os
import bcrypt
from dotenv import load_dotenv

# --- 1. Загрузка настроек из secret.env ---
# Скрипт ищет файл secret.env в той же папке, где лежит сам
env_path = os.path.join(os.path.dirname(__file__), 'secret.env')
if os.path.exists(env_path):
    load_dotenv(env_path)
else:
    print(f"⚠️ Внимание: Файл {env_path} не найден, использую переменные окружения.")

# --- 2. Настройка базы данных ---
# Импортируем create_engine и sessionmaker
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Получаем URL базы из переменных окружения
# Если переменной нет, используем стандартную 'database.db'
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./database.db")

# Создаем подключение
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# --- 3. Импорт модели пользователя ---
# Импортируем только класс User, это безопасно
from main import User

# --- 4. Функция хеширования ---
def get_password_hash(password):
    # Используем те же параметры, что и в main.py
    salt = bcrypt.gensalt(rounds=14)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

# --- 5. Основная логика ---
def change_password():
    print("\n--- Смена пароля пользователя ---")
    
    # Безопасный ввод с обработкой ошибок кодировки
    try:
        username = input("Введите логин пользователя: ").strip()
    except (UnicodeDecodeError, EOFError):
        print("❌ Ошибка ввода. Попробуйте запустить скрипт так: PYTHONIOENCODING=utf-8 python3 change_password.py")
        return

    if not username:
        print("Ошибка: Логин не может быть пустым.")
        return

    try:
        new_pass = input("Введите новый пароль: ").strip()
    except (UnicodeDecodeError, EOFError):
        print("❌ Ошибка ввода пароля.")
        return
    
    if len(new_pass) < 6:
        print("Ошибка: Пароль должен быть не менее 6 символов.")
        return

    db = SessionLocal()
    try:
        # Поиск пользователя
        user = db.query(User).filter(User.username == username).first()
        
        if user:
            # Смена пароля
            user.hashed_password = get_password_hash(new_pass)
            db.commit()
            print(f"\n✅ Успех! Пароль для пользователя '{username}' успешно изменен.")
        else:
            print(f"\n❌ Ошибка: Пользователь '{username}' не найден в базе данных.")
            print("   Проверьте правильность написания логина (регистр важен).")
            
    except Exception as e:
        print(f"\n❌ Критическая ошибка при работе с БД: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    change_password()
