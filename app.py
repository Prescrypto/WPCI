import json
import os
import config as conf

from tornado.httpclient import AsyncHTTPClient
from tornado.ioloop import IOLoop
import WSHandler

def main():
    try:
        print('response', WSHandler.get_repo_pages())
    except Exception as e:
        print(e)


if __name__ == '__main__':
    main()
    IOLoop.instance().start()