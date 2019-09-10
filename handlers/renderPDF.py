#python
import tempfile
import io
import fitz

#web
import jinja2

# internal
from models import Document, Link, signerUser
from handlers.emailHandler import Mailer
from utils import *


#google oauth
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
from googleapiclient.http import MediaIoBaseDownload


latex_jinja_env = jinja2.Environment(
    block_start_string='\BLOCK{',
    block_end_string='}',
    variable_start_string='${{',
    variable_end_string='}}$',
    comment_start_string='\#{',
    comment_end_string='}',
    line_statement_prefix='%%line',
    line_comment_prefix='%#line',
    trim_blocks=True,
    autoescape=False,
    loader=jinja2.FileSystemLoader(os.path.abspath('/'))
)

# Load Logging definition
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('tornado-info')


class renderPDF():

    document = None
    user = None
    signer_user = None
    google_credentials = None
    git_credentials = None

    def __init__(self, doc_id=None):
        if doc_id:
            try:
                doc = Document.Document()
                self.document = doc.find_by_doc_id(doc_id)
                user = User.User()
                self.user = user.find_by_attr("org_id", self.document.org_id)
            except Exception as e:
                logger.info(F"[error renderPDF init] obtaining document from docid: {str(e)}")

    def get_document_by_link_id(self, link_id):
        try:
            doc_id = "_".join(link_id.split("_")[:-1])
        except Exception as e:
            logger.info(F"[error get_document_by_link_id] obtaining link id: {str(e)}")
            return False
        try:
            doc = Document.Document()
            self.document = doc.find_by_doc_id(doc_id)
            user = User.User()
            self.user = user.find_by_attr("org_id", self.document.org_id)
        except Exception as e:
            logger.info(F"[error get_document_by_link_id] obtaining document from linkid: {str(e)}")
            return False

        return True

    def get_document_by_doc_id(self, doc_id):
        try:
            doc = Document.Document()
            self.document = doc.find_by_doc_id(doc_id)
            user = User.User()
            self.user = user.find_by_attr("org_id", self.document.org_id)
        except Exception as e:
            logger.info(F"[error get_document_by_doc_id] obtaining document from docid: {str(e)}")
            return False

        return True

    def set_google_credentials(self):

        if self.user:
            google_token = getattr(self.user, "google_token", False)
            if google_token is not False:
                self.google_credentials = {
                    'token': self.user.google_token,
                    'refresh_token': self.user.google_refresh_token,
                    'token_uri': conf.GOOGLE_TOKEN_URI,
                    'client_id': conf.GOOGLE_CLIENT_ID,
                    'client_secret': conf.GOOGLE_CLIENT_SECRET,
                    'scopes': conf.SCOPES
                }
                return True
        return False

    def render_and_sign_document(self, email, name):
        """Download and render a document then sign and send it by email"""
        b64_pdf_file = pdf_url = None
        doc_file_name = contract_file_name = ""
        render_nda_only = render_wp_only = False
        response = dict()

        try:

            doc_type = getattr(self.document, "render", "")
            self.signer_user = signerUser.SignerUser(email, name)
            # create the signer user so it can generate their keys
            self.signer_user.create()


            if doc_type == conf.GOOGLE:
                self.set_google_credentials()
                b64_pdf_file = self.render_google_document()


            elif doc_type == conf.LATEX:


            elif doc_type == conf.EXTERNAL:




            if thisdoc.nda_url is None or thisdoc.nda_url == "":
                render_wp_only = True
                if thisdoc.wp_url is None or thisdoc.wp_url == "":
                    error = "No valid Pdf url found"
                    logger.info(error)
                    return False
                else:
                    # The file name is composed by the email of the user, the link id and the timestamp of the creation
                    doc_file_name = "doc_{}_{}_{}.pdf".format(signer_user.email, link_id, timestamp_now)
                    response.update(
                        {"s3_doc_url": "{}{}view_sign_records/{}".format(conf.BASE_URL, BASE_PATH, link_id)})
                    pdf_url = thisdoc.wp_url
            else:
                pdf_url = thisdoc.nda_url
                contract_file_name = "contract_{}_{}_{}.pdf".format(signer_user.email, link_id, timestamp_now)
                response.update(
                    {"s3_contract_url": "{}{}view_sign_records/{}".format(conf.BASE_URL, BASE_PATH, link_id)})
                if thisdoc.wp_url is None or thisdoc.wp_url == "":
                    render_nda_only = True
                else:
                    doc_file_name = "doc_{}_{}_{}.pdf".format(signer_user.email, link_id, timestamp_now)
                    response.update(
                        {"s3_doc_url": "{}{}view_sign_records/{}".format(conf.BASE_URL, BASE_PATH, link_id)})


            if doc_type is not False and doc_type == "google":

            else:
                b64_pdf_file = render_pdf_base64_latex(pdf_url, "main.tex", {})

            if not b64_pdf_file:
                error = "Error rendering the pdf with the nda url"
                logger.info(error)
                return False

            thislink = Link.Link()
            thislink = thislink.find_by_link(link_id)
            temp_signed_count = thislink.signed_count
            thislink.signed_count = int(temp_signed_count) + 1
            thislink.status = "signed"
            thislink.update()

            # render and send the documents by email
            IOLoop.instance().add_callback(callback=lambda: render_and_send_docs(user, thisdoc, b64_pdf_file,
                                                                                 google_credentials_info,
                                                                                 render_wp_only,
                                                                                 render_nda_only, signer_user,
                                                                                 link_id,
                                                                                 doc_file_name, contract_file_name,
                                                                                 email_body_html, email_body_text))

            return response

        except Exception as e:
            logger.info("Checking document information {}".format(str(e)))
            return False

    def send_pdf_by_email(self):
        return None

    def download_and_sign_google_document(self, pdf_id, timestamp_now):
        MORPH = None
        watermark = "Document generated for: " + self.signer_user.email
        complete_hash = get_hash([timestamp_now, self.signer_user.email], [pdf_id])
        # Load credentials from the session.
        credentials = google.oauth2.credentials.Credentials(
            **self.google_credentials
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                file_full_path64 = tmpdir + "/" + pdf_id + ".base64"
                file_full_path = tmpdir + "/" + pdf_id + ".pdf"
                drive = googleapiclient.discovery.build(
                    conf.API_SERVICE_NAME, conf.API_VERSION, credentials=credentials)

                request = drive.files().export_media(fileId=pdf_id,
                                                     mimeType='application/pdf')
                metadata = drive.files().get(fileId=pdf_id).execute()
                file_tittle = metadata.get("title").strip(" ") + ".pdf"
                modified_date = metadata.get("modifiedDate")
                mime_type = metadata.get("mimeType")

                fh = io.BytesIO()
                downloader = MediaIoBaseDownload(fh, request, chunksize=conf.CHUNKSIZE)
                done = False
                while done is False:
                    status, done = downloader.next_chunk()

                with open(file_full_path, 'wb') as mypdf:
                    mypdf.write(fh.getvalue())

                if mime_type == "application/vnd.google-apps.presentation":
                    pointa = fitz.Point(conf.AXIS_X, conf.AXIS_Y - conf.PRESENTATION_OFFSET)
                    pointb = fitz.Point(conf.AXIS_X_LOWER, conf.AXIS_Y - conf.PRESENTATION_OFFSET)
                elif mime_type == "application/vnd.google-apps.spreadsheet":
                    pointa = fitz.Point(conf.AXIS_X, conf.AXIS_Y)
                    pointb = fitz.Point(conf.AXIS_X_LOWER, conf.AXIS_Y)

                else:
                    pointa = fitz.Point(conf.AXIS_X, conf.AXIS_Y_GOOGLE)
                    pointb = fitz.Point(conf.AXIS_X_LOWER,conf. AXIS_Y_GOOGLE)
                    MORPH = (pointb, conf.FLIP_MATRIX)

                document = fitz.open(file_full_path)
                for page in document:
                    page.insertText(pointa, text=watermark, fontsize=conf.WATERMARK_SIZE, fontname=conf.WATERMARK_FONT,
                                    rotate=conf.WATERMARK_ROTATION, morph=MORPH)
                    page.insertText(pointb, text="DocId: " + complete_hash, fontsize=conf.WATERMARK_SIZE,
                                    fontname=conf.WATERMARK_FONT, rotate=conf.WATERMARK_ROTATION, morph=MORPH)
                document.save(file_full_path, incremental=1)
                document.close()

                pdffile = open(file_full_path, 'rb').read()

                return pdffile, complete_hash, file_tittle

            except IOError as e:
                logger.info('google render IOError' + str(e))
                return None, None, None
            except Exception as e:
                logger.info("other error google render" + str(e))
                return None, None, None

    def render_doc(self, timestamp_now, tmp_dir):
        ATTACH_CONTENT_TYPE = 'octet-stream'
        doc_file_path = os.path.join(tmp_dir, conf.DOC_FILE_NAME)
        s3_file_name = "doc_{}_{}_{}.pdf".format(self.signer_user.email, self.link_id, timestamp_now)
        doc_google_id = get_id_from_url(self.document.doc_url)
        pdffile, complete_hash, file_tittle = self.download_and_sign_google_document(
            doc_google_id,
            timestamp_now
        )

        with open(doc_file_path, 'wb') as temp_file:
            temp_file.write(pdffile)

        uploaded_document_url = upload_to_s3(doc_file_path, s3_file_name)
        self.signer_user.s3_doc_url = S3_BASE_URL.format(s3_file_name)
        self.signer_user.update()
        # this is the payload for the white paper file
        doc_attachment = dict(file_type=ATTACH_CONTENT_TYPE,
                              file_path=doc_file_path,
                              filename=conf.DOC_FILE_NAME)

        return doc_attachment

    def render_google_document(self):
        """ Render and sign a google document """
        render_doc = False
        attachment_list = []
        render_contract = False
        timestamp_now = str(int(time.time()))
        error = ""
        try:
            with tempfile.TemporaryDirectory() as tmp_dir:

                try:

                    # Check which of the documents are going to be rendered
                    if self.document.type == conf.DOCUMENT:
                        render_doc = True

                    elif self.document.type == conf.CONTRACT:
                        render_contract = True

                    else:
                        render_doc = True
                        render_contract = True

                    if render_doc:
                        doc_attachment = self.render_doc_type(timestamp_now, tmp_dir)
                        attachment_list.append(doc_attachment)
                    if render_contract:
                        contract_google_id = get_id_from_url(self.document.contract_url)
                        pdffile, complete_hash, file_tittle = self.download_and_sign_google_document(contract_google_id, timestamp_now)
                        uploaded_document_url = upload_to_s3(wpci_file_path, doc_file_name)
                        signer_user.s3_doc_url = S3_BASE_URL.format(doc_file_name)
                        signer_user.update()
                        # this is the payload for the white paper file
                        wpci_attachment = dict(file_type=ATTACH_CONTENT_TYPE,
                                               file_path=wpci_file_path,
                                               filename=WPCI_FILE_NAME)
                        attachments_list.append(wpci_attachment)



            except Exception as e:
                logger.info("error rendering document: {}".format(str(e)))
                error = "error rendering document"
            finally:
                return attachments_list, error

            if not wpci_result:
                error = "Error rendering the document"
                logger.info(error)
                return attachments_list, error

            with open(wpci_file_path, 'wb') as temp_file:
                temp_file.write(wpci_result)

            uploaded_document_url = upload_to_s3(wpci_file_path, doc_file_name)
            signer_user.s3_doc_url = S3_BASE_URL.format(doc_file_name)
            signer_user.update()
            # this is the payload for the white paper file
            wpci_attachment = dict(file_type=ATTACH_CONTENT_TYPE,
                                   file_path=wpci_file_path,
                                   filename=WPCI_FILE_NAME)
            attachments_list.append(wpci_attachment)

        except Exception as e:
            logger.info("error rendering document: {}".format(str(e)))
            error = "error rendering document"
        finally:
            return attachments_list, error

    def render_latex_document(self):
        wpci_result, complete_hash, WPCI_FILE_NAME = create_download_pdf(
            thisdoc.wp_url,
            signer_user.email,
            thisdoc.main_tex)
        return None

    @gen.engine
    def render_and_send_docs(self):
        """Renders the documents and if needed send it to cryptosign and finally send it by email"""

        attachments_list = []
        doc_id = error = errornda = errorwp = ""
        mymail = Mailer(username=conf.SMTP_USER, password=conf.SMTP_PASS, host=conf.SMTP_ADDRESS, port=conf.SMTP_PORT)

        # Here we create a temporary directory to store the files while the function sends it by email
        with tempfile.TemporaryDirectory() as tmp_dir:
            try:

                if render_nda_only is False:
                    attachments_list, errornda = render_document(tmp_dir, thisdoc, doc_file_name, user,
                                                                 google_credentials_info,
                                                                 signer_user, attachments_list)
                if render_wp_only is False:
                    attachments_list, errorwp = render_contract(user, tmp_dir, nda_file_base64,
                                                                contract_file_name, signer_user, attachments_list,
                                                                link_id)
                error = errornda + errorwp
                if error != "":
                    logger.info("There was an error on the documents rendering: {}".format(error))
                else:
                    if not email_body_html:
                        email_body_html = DEFAULT_HTML_TEXT

                    # send the email with the result attachments
                    sender_format = "{} <{}>"
                    loader = Loader("templates/email")
                    button = loader.load("cta_button.html")
                    notification_subject = "Your Document {} has been downloaded".format(thisdoc.doc_id)
                    analytics_link = "{}{}analytics/{}".format(conf.BASE_URL, BASE_PATH, thisdoc.doc_id)

                    mymail.send(subject=thisdoc.wp_name,
                                email_from=sender_format.format(user.org_name, conf.SMTP_EMAIL),
                                emails_to=[signer_user.email],
                                attachments_list=attachments_list,
                                html_message=email_body_html + button.generate().decode("utf-8"),
                                text_message=email_body_text)

                    html_text = NOTIFICATION_HTML.format(signer_user.email, thisdoc.doc_id, analytics_link,
                                                         analytics_link)
                    mymail.send(subject=notification_subject,
                                attachments_list=attachments_list,
                                email_from=sender_format.format("WPCI Admin", conf.SMTP_EMAIL),
                                emails_to=[user.org_email], html_message=html_text,
                                text_message=email_body_text)

            except Exception as e:  # except from temp directory
                logger.info("[ERROR] sending the email with the documents " + str(e))

    def render_s3pdf_document(self):
        return None

    def get_b64_pdf_from_doc_id(doc_id, userjson):
        '''Call the render function and retrive a base 64 pdf'''
        result = False
        try:
            user = User.User()
            user = user.find_by_attr("username", userjson.get("username"))
            doc = Document.Document()
            docs = doc.find_by_attr("doc_id", doc_id)
            if len(docs) > 0:
                doc = docs[0]
            else:
                return result
            doc_type = getattr(doc, "type", False)
            if doc_type is False:
                google_token = getattr(user, "google_token", False)
                if google_token is not False:
                    user_credentials = {'token': user.google_token,
                                        'refresh_token': user.google_refresh_token, 'token_uri': conf.GOOGLE_TOKEN_URI,
                                        'client_id': conf.GOOGLE_CLIENT_ID,
                                        'client_secret': conf.GOOGLE_CLIENT_SECRET,
                                        'scopes': conf.SCOPES}
                    bytes = render_pdf_base64_google(doc.get("wp_url"), user_credentials)
                else:
                    return result
            else:
                bytes = render_pdf_base64_latex(doc.get("wp_url"))
            return bytes

        except Exception as e:
            logger.info("error rendering the document link " + str(e))

        return result