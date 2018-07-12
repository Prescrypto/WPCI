from handlers import routes
from tornado.wsgi import WSGIAdapter
from tornado.web import Application, FallbackHandler
from oauthApi import oauth_app


# execute asynchronously action
# print('response', WSHandler.get_repo_pages('Prescrypto/cryptosign_whitepaper/', 'README.md'))

'''Initializing the application with routes'''
web_app = Application([
        (r"/api/v1/helloworld", routes.HelloWorld),
        (r"/api/v1/renderrepo", routes.PostRepo),
        (r"/api/v1/auth/login", routes.AuthLoginHandler),
        (r"/api/v1/auth/signin", routes.RegisterUser),
        (r"/api/v1/git/(.*)", FallbackHandler, dict(fallback=oauth_app)),
        (r'.*', routes.APINotFoundHandler)],
        debug=True)

application = WSGIAdapter(web_app)


