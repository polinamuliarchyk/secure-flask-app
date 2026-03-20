import logging
import os
from datetime import datetime
from app.models import db, Alert

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(BASE_DIR, 'logs')
FALLBACK_LOG_FILE = os.path.join(LOG_DIR, 'fallback.log')


def fallback_log(message: str):
    try:
        if not os.path.exists(LOG_DIR):
            os.makedirs(LOG_DIR)

        with open(FALLBACK_LOG_FILE, "a", encoding="utf-8") as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"{timestamp} - {message}\n")
    except Exception as e:
        print(f"CRITICAL: fallback logging completely failed: {message}. Error: {e}")


def safe_add_alert(alert: Alert) -> bool:
    try:
        db.session.add(alert)
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        fallback_log(f"[DB FAILURE] Could not save alert: {alert.message}. Error: {e}")
        return False


logger = logging.getLogger('dyplom1')


def safe_graylog_warning(message: str, fields=None) -> bool:
    try:
        logger.warning(message, extra=fields or {})
        return True
    except Exception as e:
        fallback_log(f"[GRAYLOG FAILURE] {message}. Error: {e}")
        return False