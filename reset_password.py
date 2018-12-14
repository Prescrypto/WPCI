import logging

#internal
import config as conf
from models import User


# Load Logging definition
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('tornado-info')





if __name__ == "__main__":
    print("Replace the password of an User:")
    print("please enter the username followed by the new password no spaces as following:")
    admininput =input("myuser@organization,MyNewPassword")
    try:
        inputarray = admininput.split(",")
        user = User.User(inputarray[0])
        if user.find() is False:
            print("there is no such a user")
        user.validate_email(inputarray[1])
    except Exception as e:
        print(e)
