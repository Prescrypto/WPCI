from models.mongoManager import ManageDB
import pymongo
from pymongo import MongoClient
from pymongo.collation import Collation
from bson.objectid import ObjectId
import config as conf
from passlib.context import CryptContext


pwd_context = CryptContext(
        schemes=["pbkdf2_sha256"],
        default="pbkdf2_sha256",
        pbkdf2_sha256__default_rounds=300
)


class User(object):
    def __init__(self, username, password):
        self.username = username
        self.password = password

    def __str__(self):
        return "User(id='%s')" % self.username

    def encrypt_password(self):
        return pwd_context.encrypt(self.password)

    def check_encrypted_password(self, hashed):
        return pwd_context.verify(self.password, hashed)

    def find(self):
        result = False
        mydb = None
        try:
            collection = "User"
            mydb = ManageDB(collection)
            docs = mydb.select("username", self.username)
            if len(docs) > 0:
                result = True

        except Exception as e:
            print("finding user", e)

        finally:
            mydb.close()

        return result

    def check(self):
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
            print("finding user", e)

        finally:
            mydb.close()

        return result

    def create(self):
        result = False
        mydb = None
        try:
            collection = "User"
            mydb = ManageDB(collection)
            password = self.encrypt_password()
            result = mydb.insert_json({"username": self.username, "password": password})

        except Exception as error:
            print("creating user", error)

        finally:
            mydb.close()

        return result