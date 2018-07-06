import config as conf
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from handlers import WSHandler, routes
from models import mongoManager
from tornado.wsgi import WSGIContainer, WSGIAdapter
from tornado.web import Application, FallbackHandler, RequestHandler, HTTPError, os
from tornado.websocket import WebSocketHandler
from tornado.ioloop import IOLoop
from tornado.options import define, options
from handlers.routes import clone_repo



# execute asynchronously action
# print('response', WSHandler.get_repo_pages('Prescrypto/cryptosign_whitepaper/', 'README.md'))
web_app = Application([
        (r"/api/v1/helloworld", routes.HelloWorld),
        (r"/api/v1/renderrepo", routes.PostRepo),
        (r"/api/v1/auth/login", routes.AuthLoginHandler),
        (r"/api/v1/auth/signin", routes.RegisterUser),
        (r'.*', routes.APINotFoundHandler)], debug=True)

application = WSGIAdapter(web_app)


