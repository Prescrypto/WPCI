#python
from passlib.context import CryptContext
import time
import logging

#mongo db
import pymongo
from pymongo import MongoClient

#internal
from models.mongoManager import ManageDB
import config as conf
from models import User

# Load Logging definition
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('tornado-info')

DOCUMENT = "Document"
pwd_context = CryptContext(
        schemes=["pbkdf2_sha256"],
        default="pbkdf2_sha256",
        pbkdf2_sha256__default_rounds=300
)


class Document(object):
    '''The Document class include all the information needed to render a new pdf file '''

    org_id = None
    contract_url = None
    doc_url = None
    link_count = None
    view_count = None
    down_count = None
    date = None
    render = None

    def __init__(self, org_id=None):
        self.org_id = org_id
        self.contract_url = ""
        self.doc_url = ""

    def __str__(self):
        return "Document(org_id='%s')" % self.org_id

    def __setitem__(self, name, value):
        self.__dict__[name] = value

    def set_attributes(self, dictattr ):
        self.__dict__.update(dictattr)

    def create_document(self):
        try:
            self.link_count = 0
            self.view_count = 0
            self.down_count = 0
            self.date = int(time.time())

            if self.contract_url is None:
                self.contract_url = ""
            if self.doc_url is None:
                self.doc_url = ""
            if self.render is None or self.render == "":
                self.render = "google"

            if self.org_id is not None:
                user = User.User().find_by_attr("org_id", self.org_id)
                doc_name = self.doc_name.strip(" ").replace(" ", "_")
                self.doc_id = '{}_{}'.format(doc_name, str(int(time.time() * 1000)))
                result = self.create()
                if not result:
                    logger.info("couldn't save the document to the db")
                    return False

                return self.doc_id
            else:
                logger.info("theres a missing argument")
                return False
        except Exception as e:
            logger.info("error creating document "+ str(e))
            return False

    def check(self):
        '''finds a user'''
        result = False
        mydb = None
        try:
            collection = DOCUMENT
            mydb = ManageDB(collection)
            docs = mydb.select("doc_id", self.doc_id)
            if len(docs) > 0:
                result = True

        except Exception as e:
            logger.info("finding id"+ str(e))

        finally:
            if mydb is not None:
                mydb.close()

        return result

    def find_by_doc_id(self, doc_id):
        '''finds a document by the id'''
        result = None
        if doc_id is None or doc_id == "":
            return None
        try:
            doc = self.find_by_attr("doc_id", doc_id)
            if len(doc) > 0:
                self.__dict__ = doc[0]
                return self
            else:
                logger.info("doc not found")

        except Exception as e:
            logger.info("finding id"+ str(e))

        return result

    def find_by_attr(self, key, value):
        '''finds a user object by the attribute id'''
        result = []
        mydb = None
        try:
            collection = DOCUMENT
            mydb = ManageDB(collection)
            docs = mydb.select(key, value)
            if len(docs) > 0:
                result = docs

                return result
            else:
                logger.info("documents not found")

        except Exception as e:
            logger.info("finding user" + str(e))

        finally:
            if mydb is not None:
                mydb.close()

        return result

    def create(self):
        '''creates a new document on the bd'''
        result = False
        mydb = None
        if self.org_id is None or self.doc_id is None:
            return result

        try:
            collection = DOCUMENT
            mydb = ManageDB(collection)
            temp_doc = self.__dict__
            result = mydb.insert_json(temp_doc)

        except Exception as error:
            logger.info("creating document "+ str(error))

        finally:
            if mydb is not None:
                mydb.close()

        return result

    def update(self):
        '''updates a user on the bd'''
        result = None
        mydb = None
        if self.doc_id is None:
            return None
        try:
            collection = DOCUMENT
            mydb = ManageDB(collection)
            temp_doc = self.__dict__
            doc_id = temp_doc.pop("doc_id")
            temp_doc.pop("_id")

            result = mydb.update({"doc_id": doc_id}, temp_doc)

        except Exception as error:
            logger.info("updating document"+ str(error))
            result = None

        finally:
            if mydb is not None:
                mydb.close()

        return result

    def get_attribute(self, attribute_name):
        '''gets the attribute from the bd'''
        result = False
        mydb = None
        try:
            collection = DOCUMENT
            mydb = ManageDB(collection)
            docs = mydb.select("org_id", self.org_id)
            if len(docs) > 0:
                result = docs[0].get(attribute_name)
        except:
            result = None

        finally:
            if mydb is not None:
                mydb.close()

        return result
