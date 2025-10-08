# logger.py
import logging
from logging.handlers import RotatingFileHandler
import os

LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "app.log")

# Create logs directory if it doesn’t exist
os.makedirs(LOG_DIR, exist_ok=True)

# Define log format
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Configure root logger
logging.basicConfig(
    level=logging.INFO,  # or DEBUG for more detail
    format=LOG_FORMAT,
    datefmt=DATE_FORMAT,
    handlers=[
        logging.StreamHandler(),  # Console output
        RotatingFileHandler(LOG_FILE, maxBytes=2_000_000, backupCount=5)
    ]
)

def get_logger(name: str):
    """Return a logger instance with the given name."""
    return logging.getLogger(name)
