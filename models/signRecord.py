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


class SignRecord(object):
    """This model stores the txid and other parameters from rexchain response and cryptosign response"""
    def __init__(self, tx_id=None):
        self.tx_id = tx_id

    def __str__(self):
        return "SignRecord(tx_id='%s')" % self.tx_id

    def set_attributes(self, dictattr ):
        self.__dict__.update(dictattr)

    def __setitem__(self, name, value):
        self.__dict__[name] = value

    def find(self):
        '''finds a signer user by the tx_id'''
        result = False
        mydb = None
        try:
            collection = "SignRecord"
            mydb = ManageDB(collection)
            docs = mydb.select("tx_id", self.tx_id)
            if len(docs) > 0:
                result = True

        except Exception as e:
            logger.info("finding sign record "+ str(e))

        finally:
            if mydb is not None:
                mydb.close()

        return result

    def find_by_attr(self, key, value):
        '''finds a user object by the attribute id'''
        result = False
        mydb = None
        try:
            collection = "SignRecord"
            mydb = ManageDB(collection)
            docs = mydb.select(key, value)
            if len(docs) > 0:
                result = docs
            else:
                logger.info("sign record not found")

        except Exception as e:
            logger.info("finding sign record" + str(e))

        finally:
            if mydb is not None:
                mydb.close()

        return result

    def create(self):
        '''creates a new sign record on the bd'''
        result = False
        mydb = None
        try:
            collection = "SignRecord"
            mydb = ManageDB(collection)

            result = mydb.insert_json(self.__dict__)

        except Exception as error:
            logger.info("creating sign record", error)

        finally:
            if mydb is not None:
                mydb.close()

        return result

    def update(self):
        '''updates a sign record on the bd'''
        result = None
        mydb = None
        try:
            collection = "SignRecord"
            mydb = ManageDB(collection)
            temp_record = self.__dict__.copy()
            temp_record.pop("_id")

            result = mydb.update({"tx_id": self.tx_id}, temp_record)

        except Exception as error:
            logger.info("updating sign record "+ str(error))
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
            collection = "SignRecord"
            mydb = ManageDB(collection)
            docs = mydb.select("tx_id", self.tx_id)
            if len(docs) > 0:
                result = docs[0].get(attribute_name)
        except:
            result = None

        finally:
            if mydb is not None:
                mydb.close()

        return result
