from flask_mail import Mail

from flask_sqlalchemy import SQLAlchemy
import logging
import graypy


mail = Mail()
db = SQLAlchemy()

logger = logging.getLogger('dyplom1')
logger.setLevel(logging.INFO)

graylog_handler = graypy.GELFUDPHandler('192.168.36.129', 12201)
logger.addHandler(graylog_handler)

logger.info("Hello Graylog from Flask app")



