from handlers import routes
from tornado.wsgi import WSGIAdapter
from tornado.web import Application, FallbackHandler, StaticFileHandler
from oauthApi import oauth_app
import os

DOCS_BASE_PATH = "docs/"
API_BASE_PATH = "api/v1/"
cwd = os.getcwd() # used by static file server
# execute asynchronously action

'''Initializing the application with routes'''
web_app = Application([
    (r"/"+API_BASE_PATH+"helloworld", routes.HelloWorld),
    (r"/"+API_BASE_PATH+"renderrepohash", routes.PostRepoHash),
    (r"/"+API_BASE_PATH+"renderurl", routes.RenderUrl),
    (r"/"+API_BASE_PATH+"wp_nda", routes.PostWpNda),
    (r"/"+API_BASE_PATH+"login", routes.AuthLoginHandler),
    (r"/"+API_BASE_PATH+"signin", routes.RegisterUser),
    (r"/"+API_BASE_PATH+"register", routes.RegisterUserByEmail),
    (r"/"+DOCS_BASE_PATH+"(.*)", FallbackHandler, dict(fallback=oauth_app)),
    (r"/(.*\.css)", StaticFileHandler, {"path": cwd}),
    (r"/(.*\.svg)", StaticFileHandler, {"path": cwd}),
    (r'.*', routes.APINotFoundHandler)],
    debug=True)


application = WSGIAdapter(web_app)



