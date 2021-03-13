from flask import Flask
from flask_bcrypt import Bcrypt #to hash password
from flask_mail import Mail


webapp = Flask(__name__)
webapp.config['SECRET_KEY'] = '2dd7fe581baaaf399cd25056f5a2e4ae'
bcrypt = Bcrypt(webapp)


webapp.config['MAIL_SERVER']='smtp.live.com'
webapp.config['MAIL_PORT'] = 587
webapp.config['MAIL_USERNAME'] = 'ece1779a3@hotmail.com'
webapp.config['MAIL_PASSWORD'] = 'Ece1779pass'
webapp.config['MAIL_USE_TLS'] = True
webapp.config['MAIL_USE_SSL'] = False

mail = Mail(webapp)

from app import routes, forms



