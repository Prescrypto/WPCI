from tornado.web import RequestHandler
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
        self.set_status(404)
        self.finish(json.dumps({"response": "NOT FOUND"}))

    def post(self, *args, **kwargs):
        self.set_status(404)
        self.finish(json.dumps({"response": "NOT FOUND"}))

    def put(self, *args, **kwargs):
        self.set_status(404)
        self.finish(json.dumps({"response": "NOT FOUND"}))

    def delete(self, *args, **kwargs):
        self.set_status(404)
        self.finish(json.dumps({"response": "NOT FOUND"}))

    def options(self, *args, **kwargs):
        print ("in options")
        self.set_status(200)
        self.finish()
        #raise HTTPError(**status_0)

    def write_json(self, data, status_code=200):
        self.finish(json.dumps(data))