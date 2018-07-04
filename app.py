import config as conf
import datetime
import jwt
import tempfile
import os
import subprocess
import glob

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
from handlers.emailHandler import write_email


def clone_repo(repo_url):
    repo_name = ''
    new_name = ''
    try:
        repo_name= repo_url.split("/")[-1].split(".")[0]
    except Exception as e:
        print('couldnt find the name or not valid url')
        return("ERROR")

    clone = "git clone " + repo_url
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            filesdir = os.path.join(tmpdir, repo_name)
            subprocess.call(clone, shell=True, cwd=tmpdir)
            files = glob.glob(filesdir + '/*.tex')

            for name in files:
                subprocess.call("pdflatex "+ name, shell=True, cwd=tmpdir)
                try:
                    new_name = name.split("/")[-1].split(".")[0] + ".pdf"
                except:
                    print("main file name not found")
                    return("ERROR ON MAIN FILE")

                write_email(["valerybriz@gmail.com"], "testing pdflatex",new_name , tmpdir+"/")
                #print('name', name)
                #with open(name) as tmp:
                #    print(tmp)

        except IOError as e:
            print('IOError', e)

        finally:
            print('finally')


def main():
    try:
        #print('response', WSHandler.get_repo_pages('Prescrypto/cryptosign_whitepaper/', 'README.md'))
        clone_repo('https://github.com/Prescrypto/cryptosign_whitepaper.git')

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
