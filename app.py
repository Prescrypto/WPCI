import config as conf
import datetime
import jwt

from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from handlers import WSHandler, routes
from models import mongoManager
from tornado.wsgi import WSGIContainer
from tornado.web import Application, FallbackHandler, RequestHandler, HTTPError, os
from tornado.websocket import WebSocketHandler
from tornado.ioloop import IOLoop
from tornado.options import define, options
PORT = conf.LISTEN_PORT

def main():
    try:
        print('response', WSHandler.get_repo_pages('Prescrypto/cryptosign_whitepaper/', 'README.md'))
    except Exception as e:
        print(e)


if __name__ == '__main__':
    main()
    #IOLoop.instance().start()

    try:
        application = routes.application
        httpServer = HTTPServer(application)
        httpServer.listen(PORT)
        httpServer.start()
        # application.listen(5000)
        IOLoop.instance().start()
    except KeyboardInterrupt:
        IOLoop.instance().stop()
        print("keyboard interrupt")
    except Exception as e:
        print(e)
