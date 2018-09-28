from models.mongoManager import ManageDB
import pymongo
from pymongo import MongoClient
import config as conf
from passlib.context import CryptContext
import time
import logging
from models import User

# Load Logging definition
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('tornado-info')

NDA = "Nda"
pwd_context = CryptContext(
        schemes=["pbkdf2_sha256"],
        default="pbkdf2_sha256",
        pbkdf2_sha256__default_rounds=300
)


class Document(object):

    def __init__(self, org_id = None):
        self.org_id = org_id

    def __str__(self):
        return "Nda(org_id='%s')" % self.org_id

    def __setitem__(self, name, value):
        self.__dict__[name] = value

    def set_attributes(self, dictattr ):
        self.__dict__.update(dictattr)

    def create_nda(self):
        try:

            if self.nda_url is not None and self.wp_url is not None and self.org_id is not None:
                user = User.User().find_by_attr("org_id", self.org_id)

                self.nda_id = '{}_nda_{}'.format(user.org_name.strip().strip("."), str(int(time.time() * 1000)))
                result = self.create()
                logger.info("create result", result)
                if not result:
                    logger.info("couldn't save the nda to the db")
                    return False

                return self.nda_id
            else:
                logger.info("theres a missing argument")
                return False
        except Exception as e:
            logger.info("error creating nda "+ str(e))
            return False

    def check(self):
        '''finds a user'''
        result = False
        mydb = None
        try:
            collection = NDA
            mydb = ManageDB(collection)
            docs = mydb.select("id", self.id)
            if len(docs) > 0:
                result = True

        except Exception as e:
            logger.info("finding id"+ str(e))

        finally:
            if mydb is not None:
                mydb.close()

        return result

    def find_by_nda_id(self, nda_id):
        '''finds a user'''
        result = None
        mydb = None
        if id is None or id == "":
            return None
        try:
            collection = NDA
            mydb = ManageDB(collection)
            docs = mydb.select("nda_id", nda_id)
            if len(docs) > 0:
                self.__dict__ = docs[0]
                return self

        except Exception as e:
            logger.info("finding id"+ str(e))

        finally:
            if mydb is not None:
                mydb.close()

        return result

    def create(self):
        '''creates a new user on the bd'''
        result = False
        mydb = None
        if self.org_id is None or self.nda_id is None:
            return result

        try:
            collection = NDA
            mydb = ManageDB(collection)
            temp_nda = self.__dict__
            logger.info("before create ", result)
            result = mydb.insert_json(temp_nda)

        except Exception as error:
            logger.info("creating user "+ str(error))

        finally:
            if mydb is not None:
                mydb.close()

        return result

    def update(self):
        '''updates a user on the bd'''
        result = None
        mydb = None
        if self.nda_id is None:
            return None
        try:
            collection = NDA
            mydb = ManageDB(collection)
            temp_nda= self.__dict__
            temp_nda.pop("nda_id")
            result = mydb.update({"nda_id": self.nda_id}, temp_nda)

        except Exception as error:
            logger.info("updating user"+ str(error))
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
            collection = NDA
            mydb = ManageDB(collection)
            docs = mydb.select("id", self.id)
            if len(docs) > 0:
                result = docs[0].get(attribute_name)
        except:
            result = None

        finally:
            if mydb is not None:
                mydb.close()

        return result