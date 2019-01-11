#python
from passlib.context import CryptContext
import time
import logging
import subprocess
import tempfile
import os

#mongo db
import pymongo
from pymongo import MongoClient

#internal
from models.mongoManager import ManageDB
import config as conf
from models import User, Document

# Load Logging definition
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('tornado-info')

LINK = "Link"


class Link(object):
    '''This class is a Link so the user can sign a Document and also the company can get statistics'''

    def __init__(self, doc_id = None):
        self.doc_id = doc_id

    def __str__(self):
        return "Link(doc_id='%s')" % self.doc_id

    def __setitem__(self, name, value):
        self.__dict__[name] = value

    def set_attributes(self, dictattr):
        self.__dict__.update(dictattr)

    def create_link(self):
        self.status = "unsigned"
        self.view_count = 0
        self.signed_count = 0
        self.version = "0"
        if self.doc_id is not None:
            document = Document.Document()
            thisdocument = document.find_by_nda_id(self.doc_id)
            new_link_count  = getattr(thisdocument, "link_count", 0)
            new_link_count += 1
            self.link = self.doc_id + "_" + str( new_link_count )
            thisdocument.link_count = new_link_count
            thisdocument.update()
            if thisdocument.render == "latex":
                '''If the document has a repo then we can name the version after the last commit'''
                with tempfile.TemporaryDirectory() as tmpdir:
                    clone = 'git clone ' + thisdocument.wp_url
                    subprocess.check_output(clone, shell=True, cwd=tmpdir)
                    repo_name = os.listdir(tmpdir)[0]
                    filesdir = os.path.join(tmpdir, repo_name)
                    myoutput = subprocess.check_output("git rev-parse HEAD", shell=True, cwd=filesdir)
                    self.version = myoutput.decode(encoding="ascii", errors="ignore")
                    self.version = self.version.rstrip()

            result = self.create()
        else:
            return False

        return self.link

    def delete_link(self):
        if self.doc_id is not None:
            mylink = self.find_by_link(self.doc_id)
            mylink.status = "deleted"
            result = mylink.update()
        else:
            return False

        return result

    def create(self):
        '''creates a new link on the bd'''
        result = False
        mydb = None
        if self.doc_id is None or self.link is None:
            return result

        try:
            collection = LINK
            mydb = ManageDB(collection)
            temp_link = self.__dict__
            result = mydb.insert_json(temp_link)

        except Exception as error:
            logger.info("creating link "+ str(error))

        finally:
            if mydb is not None:
                mydb.close()

        return result

    def update(self):
        '''updates a link on the bd'''
        result = False
        mydb = None
        if self.doc_id is None:
            return False
        try:
            collection = LINK
            mydb = ManageDB(collection)
            temp_link= self.__dict__
            link_id = temp_link.pop("link")
            temp_link.pop("_id")

            result = mydb.update({"link": link_id}, temp_link)

        except Exception as error:
            logger.info("updating link" + str(error))
            result = False

        finally:
            if mydb is not None:
                mydb.close()

        return result

    def find_by_link(self, link):
        '''finds a link by the id'''
        result = None
        if not link:
            return result
        try:
            mylink = self.find_by_attr("link", link)
            if len(mylink) > 0:
                self.__dict__ = mylink[0]
                return self
            else:
                logger.info("link not found")

        except Exception as e:
            logger.info("finding id on links"+ str(e))

        return result


    def find_by_attr(self, key, value):
        '''finds a user object by the attribute id'''
        result = []
        mydb = None
        try:
            collection = LINK
            mydb = ManageDB(collection)
            docs = mydb.select(key, value)
            if len(docs) > 0:
                result = docs

                return result
            else:
                logger.info("documents not found on bd")

        except Exception as e:
            logger.info("finding link" + str(e))

        finally:
            if mydb is not None:
                mydb.close()

        return result

