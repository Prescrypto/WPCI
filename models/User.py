from models.mongoManager import ManageDB
import pymongo
from pymongo import MongoClient
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
        self.github_token = None

    def __str__(self):
        return "User(id='%s')" % self.username

    def encrypt_password(self):
        return pwd_context.encrypt(self.password)

    def check_encrypted_password(self, hashed):
        return pwd_context.verify(self.password, hashed)

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
            print("finding user", e)

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
            print("finding user", e)

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
            password = self.encrypt_password()
            result = mydb.insert_json({"username": self.username, "password": password})

        except Exception as error:
            print("creating user", error)

        finally:
            if mydb is not None:
                mydb.close()

        return result

    def update(self):
        '''updates a user on the bd'''
        result = False
        mydb = None
        try:
            collection = "User"
            mydb = ManageDB(collection)
            temp_user= self.__dict__
            temp_user.pop("password")
            result = mydb.update({"username": self.username}, temp_user)

        except Exception as error:
            print("updating user", error)

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
                return docs[0].get(attribute_name)
        except:
            return None