import config as conf
import datetime
import jwt
import tempfile
import os
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


def clone_repo(repo_url):
    try:
        repo_name= repo_url.split("/")[-1].split(".")[0]
    except Exception as e:
        print('couldnt find the name or not valid url')
        return("ERROR")

    clone = "git clone " + repo_url
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            filesdir = os.path.join(tmpdir, repo_name)
            os.chdir(tmpdir)  # Specifying the path where the cloned project has to be copied
            os.system(clone)  # Cloning
            files = glob.glob(filesdir + '/*.tex')

            for name in files:
                #print('name', name)
                with open(name) as tmp:
                    print(tmp)

        except IOError as e:
            print('IOError', e)

        finally:
            print('finally')

def clone_repo3(repo_url):
    tmpdir = tempfile.mkdtemp()
    clone = "git clone "+ repo_url

    try:
        filesdir = os.path.join(tmpdir, 'cryptosign_whitepaper')
        print(filesdir)
        #files = glob.glob(filesdir+ '/*.tex')

        os.chdir(tmpdir)  # Specifying the path where the cloned project has to be copied
        os.system(clone)  # Cloning
        files = glob.glob(filesdir+ '/*.tex')

        for name in files:
            print('name',name)
            with open(name) as tmp:
                for line in tmp:
                    print(line)
            #os.remove(path)

    except IOError as e:
        print('IOError', e)

    finally:
        #os.umask(saved_umask)
        #os.rmdir(tmpdir)
        print('finally')

def clone_repo2(repo_url):
    tmpdir = tempfile.mkdtemp()
    predictable_filename = 'myfile.txt'

    # Ensure the file is read/write by the creator only
    #saved_umask = os.umask(0o777)

    path = os.path.join(tmpdir, predictable_filename)
    print(path)
    try:
        with open(path, "w") as tmp:
            tmp.write("secrets!")
        with open(path, "r") as tmp:
            line = tmp.readline()
            print(line)
        #os.remove(path)

    except IOError as e:
        print('IOError', e)

    finally:
        #os.umask(saved_umask)
        os.rmdir(tmpdir)
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
