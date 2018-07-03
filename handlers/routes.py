from tornado.wsgi import WSGIContainer
from tornado.web import Application, FallbackHandler, RequestHandler, HTTPError, os
from tornado.websocket import WebSocketHandler
import tornado
from tornado.ioloop import IOLoop
from tornado.options import define, options
from handlers.apiBaseHandler import BaseHandler
import jwt
import config as conf
import datetime
import json
from models import User

SECRET = conf.SECRET


def encode_auth_token(user):
    """
    Generates the Auth Token
    :return: string
    """
    try:
        payload = {
            "exp": datetime.datetime.utcnow() + datetime.timedelta(days=1, seconds=3600),
            "iat": datetime.datetime.utcnow(),
            "username": user.username,
            "password": user.password
        }
        return jwt.encode(
            payload,
            SECRET,
            algorithm="HS256"
        )
    except Exception as e:
        return e


def decode_auth_token(auth_token):
    """
    Decodes the auth token
    :param auth_token:
    :return: json user
    """
    try:
        payload = jwt.decode(auth_token, SECRET)
        return payload
    except jwt.ExpiredSignatureError:
        return 'Signature expired. Please log in again.'
    except jwt.InvalidTokenError:
        return 'Invalid token. Please log in again.'


def authenticate(password, username):
    if not (username and password):
        return False

    user = User.User(username, password)
    if user.check():
        token_auth = encode_auth_token(user)

        return token_auth

    else:
        return False

def validate_token(access_token):
    """Verifies that an access-token is valid and
    meant for this app."""
    try:
        method, token = access_token.split(" ")
        user_id = decode_auth_token(token.strip('"'))

    except Exception as e:
        print (e)
        return False

    return user_id


def jwtauth(handler_class):
    ''' Handle Tornado JWT Auth '''
    userid = None
    def wrap_execute(handler_execute):
        def require_auth(handler, kwargs):
            auth = handler.request.headers.get('Authorization')

            if auth:
                parts = auth.split()

                if parts[0].lower() != 'bearer':
                    handler._transforms = []
                    handler.set_status(401)
                    handler.write("invalid header authorization")
                    handler.finish()
                elif len(parts) == 1:
                    handler._transforms = []
                    handler.set_status(401)
                    handler.write("invalid header authorization")
                    handler.finish()
                elif len(parts) > 2:
                    handler._transforms = []
                    handler.set_status(401)
                    handler.write("invalid header authorization")
                    handler.finish()

                try:
                    userid = validate_token(auth)

                    if userid is False:
                        handler._transforms = []
                        handler.set_status(403)
                        handler.write("Forbidden")
                        handler.finish()

                    if 'username' not in userid:
                        handler._transforms = []
                        handler.set_status(401)
                        handler.write("Forbidden")
                        handler.finish()

                    kwargs["userid"] = str(userid)

                except Exception as e:
                    handler._transforms = []
                    handler.set_status(401)
                    handler.write(e)
                    handler.finish()
            else:
                handler._transforms = []
                handler.write("Missing authorization")
                handler.finish()

            return True

        def _execute(self, transforms, *args, **kwargs):

            try:
                require_auth(self, kwargs)
            except Exception as e:
                print (e)
                return False

            return handler_execute(self, transforms, *args, **kwargs)

        return _execute

    handler_class._execute = wrap_execute(handler_class._execute)
    return handler_class


def authenticate_json(json_data):
    try:
        username = json_data.get("username")
        password = json_data.get("password")
    except:
        return False

    if not (username and password):
        return False

    user = User.User(username,password)

    if user.check():
        token_auth = encode_auth_token(user)

        return token_auth.decode("utf-8")

    else:
        return False

@jwtauth
class APINotFoundHandler(BaseHandler):
    def options(self, *args, **kwargs):
        self.set_status(200)
        self.finish()

class AuthLoginHandler(BaseHandler):
    def get(self):
        try:
            errormessage = self.get_argument("error")
        except:
            errormessage = ""
        #self.render("login.html", errormessage = errormessage)
        self.write_json({"response":"error"}, 200)

    def post(self):
        json_data = json.loads(self.request.body.decode('utf-8'))
        token_auth = authenticate_json(json_data)
        if token_auth is False:
            status_code =401
            response = {'status': '401', 'message': 'Incorrect username or password'}
        else:
            status_code = 200
            response = {"token": token_auth}

        self.write_json(response, status_code)

    def set_current_user(self, user):
        if user:
            self.set_secure_cookie("user", tornado.escape.json_encode(user))
        else:
            self.clear_cookie("user")

class RegisterUser(BaseHandler):
    def post(self):
        json_data = json.loads(self.request.body.decode('utf-8'))
        user = User.User(json_data.get("username"), json_data.get("password"))
        if not user.find():
            user.create()

@jwtauth
class HelloWorld2(BaseHandler):
    def get(self, userid):
        self.write(json.dumps({"response": "hello world2"}))

    def post(self, userid):
        self.write(json.dumps({"response": "hello world2"}))


class HelloWorld(BaseHandler):
    def get(self):
        self.write(json.dumps({"response": "hello world"}))

    def post(self):
        self.write(json.dumps({"response": "hello world"}))



application = Application([
        (r"/api/v1/helloworld", HelloWorld),
        (r"/api/v1/helloworld2", HelloWorld2),
        (r"/api/v1/auth/login", AuthLoginHandler),
        (r"/api/v1/auth/signin", RegisterUser),
        (r'.*', APINotFoundHandler)], debug=True)