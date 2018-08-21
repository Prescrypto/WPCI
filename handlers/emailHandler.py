from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from tornado.template import Loader
from email import encoders
import config as conf
import smtplib


class Mailer(object):
    def __init__(self, **kwargs):
        mandatory_args = ["username","password","server","port"]
        for x in mandatory_args:
            if kwargs.get(x, False) == False:
                raise ValueError("%s must be provided" % (x))
            self.__dict__[x] = kwargs[x]
        loader = Loader("templates/email")
        self.EMAIL_HTML_TEMPLATE = loader.load("document_send_email.html")
        self.server = smtplib.SMTP(host=self.server, port=self.port)

    def send(self, **kwargs):
        mandatory_args = ["subject","email_from","emails_to","attachments_list"]
        for x in mandatory_args:
            if not kwargs.get(x, False):
                raise ValueError("%s is mandatory" % (x))

        toaddr_list = []
        for eaddress in kwargs['emails_to']:
            toaddr_list.append(eaddress)

        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = kwargs['subject']
            msg['From'] = kwargs['email_from']
            msg['To'] = ','.join(kwargs['emails_to'])

            text = kwargs['text_message']
            html = kwargs['html_message']
            attachments_list = kwargs['attachments_list']
            if text is not None and text != "":
                msg.attach(MIMEText(text, 'plain'))
            if html is not None and html != "":
                html = self.EMAIL_HTML_TEMPLATE.generate(body_msg=html)
                msg.attach(MIMEText(html.decode("utf-8") , 'html'))

            for attachment in attachments_list:
                part = MIMEBase('application', attachment.get("file_type"))
                part.set_payload(open(attachment.get("file_path"), "rb").read())
                encoders.encode_base64(part)
                part.add_header('Content-Disposition', 'attachment; filename="' + attachment.get('filename') + '"')
                msg.attach(part)

            self.server.starttls()
            self.server.login(self.username, self.password)
            self.server.sendmail(msg['From'], msg['To'], msg.as_string())
            print(self.server.quit())
        except Exception as e:
            print("error sending email", e)
