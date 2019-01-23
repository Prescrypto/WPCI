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
from utils import *

# Load Logging definition
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('tornado-info')


class SignerUser(object):

    def __init__(self, email=None, name=None):
        self.email = email
        self.name = name
        self.pub_key = None
        self.priv_key = None
        self.sign = None

    def __str__(self):
        return "SignerUser(email='%s')" % self.email

    def set_attributes(self, dictattr ):
        self.__dict__.update(dictattr)

    def __setitem__(self, name, value):
        self.__dict__[name] = value


    def find(self):
        '''finds a signer user by the email'''
        result = False
        mydb = None
        try:
            collection = "SignerUser"
            mydb = ManageDB(collection)
            docs = mydb.select("email", self.email)
            if len(docs) > 0:
                result = True

        except Exception as e:
            logger.info("finding signer user"+ str(e))

        finally:
            if mydb is not None:
                mydb.close()

        return result

    def find_by_attr(self, key, value):
        '''finds a user object by the attribute id'''
        result = False
        mydb = None
        try:
            collection = "SignerUser"
            mydb = ManageDB(collection)
            docs = mydb.select(key, value)
            if len(docs) > 0:
                self.__dict__ = docs[0]
                return self
            else:
                logger.info("signer user not found")

        except Exception as e:
            logger.info("finding signer user" + str(e))

        finally:
            if mydb is not None:
                mydb.close()

        return result

    def create(self):
        '''creates a new user on the bd'''
        result = False
        mydb = None
        try:
            collection = "SignerUser"
            mydb = ManageDB(collection)
            crypto_tool = CryptoTools()

            if not self.pub_key or not self.priv_key:
                # creating RSA keys for the signer user
                crypto_tool.entropy(int(str(time.time())[-4:]))
                public_key, private_key = crypto_tool.create_key_with_entropy()
                self.priv_key = crypto_tool.get_pem_format(private_key).decode("utf-8")
                self.pub_key = crypto_tool.get_pem_format(public_key).decode("utf-8")

            else:
                logger.info("keys already created")

            # Use the signer email and name to create a signature for it
            signer_signature = self.email + self.name
            self.sign = crypto_tool.sign(
                signer_signature.encode('utf-8'),
                crypto_tool.import_RSA_string(self.priv_key)
            ).decode('utf-8')

            result = mydb.insert_json(self.__dict__)

        except Exception as error:
            logger.info("creating user", error)

        finally:
            if mydb is not None:
                mydb.close()

        return result

    def update(self):
        '''updates a email on the bd'''
        result = None
        mydb = None
        try:
            collection = "SignerUser"
            mydb = ManageDB(collection)
            temp_user = self.__dict__

            result = mydb.update({"email": self.email}, temp_user)

        except Exception as error:
            logger.info("updating email "+ str(error))
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
            collection = "SignerUser"
            mydb = ManageDB(collection)
            docs = mydb.select("email", self.email)
            if len(docs) > 0:
                result = docs[0].get(attribute_name)
        except:
            result = None

        finally:
            if mydb is not None:
                mydb.close()

        return result
