try:
    from email.MIMEMultipart import MIMEMultipart
except:
    from email.mime.multipart import MIMEMultipart
try:
    from email.MIMEBase import MIMEBase
except:
    from email.mime.base import MIMEBase
from email import encoders
import config as conf
import smtplib

SMTP_PASS = conf.SMTP_PASS
SMTP_USER = conf.SMTP_USER
SMTP_EMAIL = conf.SMTP_EMAIL
SMTP_ADDRESS = conf.SMTP_ADDRESS
SMTP_PORT = conf.SMTP_PORT

def write_email(to_addr_list, subject, filename,path):
    msg = MIMEMultipart()
    toaddr_list = []
    from_addr = SMTP_EMAIL
    for eaddress in to_addr_list:
        toaddr_list.append(eaddress)

    if subject == '':
        subject = 'SUBJECT'

    msg['Subject'] = subject
    msg['From'] = from_addr
    msg['To'] = ','.join(to_addr_list)
    login = SMTP_USER
    password = SMTP_PASS

    # ATTACHMENT
    part = MIMEBase('application', "octet-stream")
    part.set_payload(open(path, "rb").read())
    encoders.encode_base64(part)
    part.add_header('Content-Disposition', 'attachment; filename="'+filename+'"')
    msg.attach(part)

    try:
        server = smtplib.SMTP(host=SMTP_ADDRESS, port=SMTP_PORT, )
        server.starttls()
        server.login(login, password)
        server.sendmail(from_addr, toaddr_list, msg.as_string())
        print ("email sent")
        print (server.quit())
    except Exception as e:
        print("sending email", e)