from handlers import routes
from tornado.wsgi import WSGIAdapter
from tornado.web import Application, FallbackHandler, StaticFileHandler
from oauthApi import oauth_app
import os

cwd = os.getcwd() # used by static file server
# execute asynchronously action
# print('response', WSHandler.get_repo_pages('Prescrypto/cryptosign_whitepaper/', 'README.md'))

'''Initializing the application with routes'''
web_app = Application([
    (r"/api/v1/helloworld", routes.HelloWorld),
    (r"/api/v1/renderrepohash", routes.PostRepoHash),
    (r"/api/v1/renderurl", routes.RenderUrl),
    (r"/api/v1/auth/login", routes.AuthLoginHandler),
    (r"/api/v1/auth/signin", routes.RegisterUser),
    (r"/api/v1/git/(.*)", FallbackHandler, dict(fallback=oauth_app)),
    (r"/(.*\.css)", StaticFileHandler, {"path": cwd}),
    (r'.*', routes.APINotFoundHandler)],
    debug=True)


application = WSGIAdapter(web_app)



