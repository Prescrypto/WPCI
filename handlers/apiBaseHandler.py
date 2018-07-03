from tornado.wsgi import WSGIContainer
from tornado.web import Application, FallbackHandler, HTTPError, os
from tornado.web import RequestHandler
from tornado.websocket import WebSocketHandler
from tornado.ioloop import IOLoop
from tornado.options import define, options
import json

class BaseHandler(RequestHandler):
    def data_received(self, chunk):
        pass

    def __init__(self, application, request, **kwargs):
        RequestHandler.__init__(self, application, request, **kwargs)
        self.set_header("Content-Type", "text/html; charset=utf-8")
        self.set_header("Access-Control-Allow-Origin", "*")
        self.set_header("Access-Control-Allow-Headers", "X-Requested-With, Content-Type, Origin, Authorization, Accept, Client-Security-Token, Accept-Encoding")
        self.set_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE, HEAD")
        self.set_header("Vary", "Origin")


    def get(self, *args, **kwargs):
        raise HTTPError(**status_0)

    def post(self, *args, **kwargs):
        raise HTTPError(**status_0)

    def put(self, *args, **kwargs):
        raise HTTPError(**status_0)

    def delete(self, *args, **kwargs):
        raise HTTPError(**status_0)

    def options(self, *args, **kwargs):
        print ("in options")
        self.set_status(200)
        self.finish()
        #raise HTTPError(**status_0)

    def write_json(self, data, status_code=200):
        self.finish(json.dumps(data))