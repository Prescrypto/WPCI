import logging
import click
#internal
import config as conf
from models import User


# Load Logging definition
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('tornado-info')

@click.command()
@click.option('--username', default="", help='The user name to login')
@click.option('--password', default="", help='The password of your user')

def reset_password():
    try:
        user = User.User(username)
        if user.find() is False:
            print("there is no such a user")
        user.validate_email(password)
    except Exception as e:
        print(e)

if __name__ == "__main__":
    reset_password()

