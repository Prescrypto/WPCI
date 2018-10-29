#python
import time
import logging

#mongodb
import pymongo
from pymongo import MongoClient
from passlib.context import CryptContext

#internal
from models.mongoManager import ManageDB
import config as conf
from utils import get_hash

# Load Logging definition
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('tornado-info')


pwd_context = CryptContext(
        schemes=["pbkdf2_sha256"],
        default="pbkdf2_sha256",
        pbkdf2_sha256__default_rounds=300
)

class User(object):

    def __init__(self, username=None, password=None):
        self.username = username
        self.password = password
        self.github_token = None


    def __str__(self):
        return "User(username='%s')" % self.username

    def encrypt_password(self, password):
        return pwd_context.encrypt(password)

    def check_encrypted_password(self, hashed):
        return pwd_context.verify(self.password, hashed)

    def get_validation_code(self):
        self.code = get_hash([self.username])
        if self.find():
            print("user already exists")
            return False
        self.create()
        return self.code

    def validate_email(self, password):
        self.password = self.encrypt_password(password)
        self.update(update_password=True)

    def set_attributes(self, dictattr ):
        self.__dict__.update(dictattr)

    def __setitem__(self, name, value):
        self.__dict__[name] = value


    def find(self):
        '''finds a user'''
        result = False
        mydb = None
        try:
            collection = "User"
            mydb = ManageDB(collection)
            docs = mydb.select("username", self.username)
            if len(docs) > 0:
                result = True

        except Exception as e:
            logger.info("finding user"+ str(e))

        finally:
            if mydb is not None:
                mydb.close()

        return result

    def find_by_attr(self, key, value):
        '''finds a user object by the attribute id'''
        result = False
        mydb = None
        try:
            collection = "User"
            mydb = ManageDB(collection)
            docs = mydb.select(key, value)
            if len(docs) > 0:
                self.__dict__ = docs[0]
                return self
            else:
                logger.info("user not found")

        except Exception as e:
            logger.info("finding user" + str(e))

        finally:
            if mydb is not None:
                mydb.close()

        return result

    def check(self):
        '''checks if username and password exists'''
        result = False
        mydb = None
        try:
            collection = "User"
            mydb = ManageDB(collection)
            docs = mydb.select("username", self.username)
            for doc in docs:
                if self.check_encrypted_password(doc.get("password")):
                    result = True

        except Exception as e:
            logger.info("finding user"+ str(e))

        finally:
            if mydb is not None:
                mydb.close()

        return result

    def create(self):
        '''creates a new user on the bd'''
        result = False
        mydb = None
        try:
            collection = "User"
            mydb = ManageDB(collection)
            if self.password is not None:
                password = self.encrypt_password(self.password)
            else:
                password = ""
            if self.code is not None:
                code = self.code
            else:
                code = ""
            org_id = self.username + str(int(time.time()))
            result = mydb.insert_json({"username": self.username, "password": password, "org_id": org_id, "code": code})

        except Exception as error:
            logger.info("creating user", error)

        finally:
            if mydb is not None:
                mydb.close()

        return result

    def update(self, update_password = False):
        '''updates a user on the bd'''
        result = None
        mydb = None
        try:
            collection = "User"
            mydb = ManageDB(collection)
            temp_user= self.__dict__
            if not update_password:
                print("no password update")
                temp_user.pop("password")
            result = mydb.update({"username": self.username}, temp_user)

        except Exception as error:
            logger.info("updating user "+ str(error))
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
            collection = "User"
            mydb = ManageDB(collection)
            docs = mydb.select("username", self.username)
            if len(docs) > 0:
                result = docs[0].get(attribute_name)
        except:
            result = None

        finally:
            if mydb is not None:
                mydb.close()

        return result