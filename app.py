#python
import os
import logging

#web app
#from tornado.wsgi import WSGIAdapter
from tornado.web import Application, FallbackHandler, StaticFileHandler
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop

#internal
from handlers import routes
from oauthApi import oauth_app
import config as conf

# Load Logging definition
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('tornado-info')

DOCS_BASE_PATH = "docs/"
API_BASE_PATH = "api/v1/"
LISTEN_PORT = conf.LISTEN_PORT
cwd = os.getcwd() # used by static file server
# execute asynchronously action

# When running locally, disable OAuthlib's HTTPs verification.
# ACTION ITEM for developers:
#     When running in production *do not* leave this option enabled.
#os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'




if __name__ == '__main__':
    ''''
    Initializing the application with routes'''
    web_app = Application([
        (r"/"+API_BASE_PATH+"doc_edit", routes.DocEdit),
        (r"/" + API_BASE_PATH + "testhandler", routes.TestHandler),
        (r"/"+API_BASE_PATH+"doc_status", routes.DocStatus),
        (r"/"+API_BASE_PATH+"doc_get", routes.DocRenderPDF),
        (r"/"+API_BASE_PATH+"renderrepohash", routes.PostRepoHash),
        (r"/"+API_BASE_PATH+"renderurl", routes.RenderUrl),
        (r"/"+API_BASE_PATH+"wp_nda", routes.PostWpNda),
        (r"/"+API_BASE_PATH+"login", routes.AuthLoginHandler),
        (r"/"+API_BASE_PATH+"signin", routes.RegisterUser),
        (r"/"+API_BASE_PATH+"register", routes.RegisterUserByEmail),
        (r"/"+API_BASE_PATH+"payments/webhook/confirmation", routes.WebhookConfirm),
        (r"/"+API_BASE_PATH+"pdf/(.*)", FallbackHandler, dict(fallback=oauth_app)),
        (r"/"+DOCS_BASE_PATH+"(.*)", FallbackHandler, dict(fallback=oauth_app)),
        (r"/", FallbackHandler, dict(fallback=oauth_app)),
        (r"/(.*\.css)", StaticFileHandler, {"path": cwd}),
        (r"/(.*\.js)", StaticFileHandler, {"path": cwd}),
        (r"/(.*\.svg)", StaticFileHandler, {"path": cwd}),
        (r"/(.*\.txt)", StaticFileHandler, {"path": cwd}),
        (r'.*', routes.APINotFoundHandler)],
        debug=True)

    try:
        httpServer = HTTPServer(web_app)
        httpServer.listen(LISTEN_PORT)
        httpServer.start()
        IOLoop.instance().start()
    except KeyboardInterrupt:
        IOLoop.instance().stop()
        logger.info("keyboard interrupt")
    except Exception as e:
        logger.info(e)

#application = WSGIAdapter(web_app)



