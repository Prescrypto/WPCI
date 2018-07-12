import config as conf
from handlers import WSHandler, routes
from models import mongoManager
from tornado.wsgi import WSGIContainer, WSGIAdapter
from tornado.web import Application

# execute asynchronously action
# print('response', WSHandler.get_repo_pages('Prescrypto/cryptosign_whitepaper/', 'README.md'))
'''Initializing the application with routes'''
web_app = Application([
        (r"/api/v1/helloworld", routes.HelloWorld),
        (r"/api/v1/renderrepo", routes.PostRepo),
        (r"/api/v1/auth/login", routes.AuthLoginHandler),
        (r"/api/v1/auth/signin", routes.RegisterUser),
        (r'.*', routes.APINotFoundHandler)], debug=True)

application = WSGIAdapter(web_app)

