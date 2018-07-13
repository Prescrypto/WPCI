import os
from models import User
import config as conf


user = User.User(conf.ADMIN_USER, conf.ADMIN_PASS)
user.create()