import logging
import os
from logging.handlers import RotatingFileHandler

# Создаем папку для логов, если её нет
if not os.path.exists('logs'):
    os.makedirs('logs')

# Формат логов: Время | Уровень | Сообщение
log_format = "%(asctime)s - [%(levelname)s] - %(message)s"
date_format = "%Y-%m-%d %H:%M:%S"

# Настройка хендлера (ротация: 1 файл = 5 МБ, храним 3 последних файла)
file_handler = RotatingFileHandler(
    'logs/app.log', 
    maxBytes=5*1024*1024, 
    backupCount=3,
    encoding='utf-8'
)
file_handler.setFormatter(logging.Formatter(log_format, datefmt=date_format))

# Настройка вывода в консоль (для просмотра через docker logs или ssh)
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter(log_format, datefmt=date_format))

# Основной логгер
logger = logging.getLogger("rostov_bot")
logger.setLevel(logging.INFO) # Уровень INFO (пропускает INFO, WARNING, ERROR)
logger.addHandler(file_handler)
logger.addHandler(console_handler)

def get_logger():
    return logger
