#python
import tempfile
import io
import fitz
import subprocess
import requests

#web
import jinja2
from tornado import gen

# internal
from models import Document, Link, signerUser
from handlers.emailHandler import Mailer
from utils import *
from handlers.WSHandler import get_b2h_document

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

#HTML EMAIL TEMPLATES
DEFAULT_HTML_TEXT = \
            "<h3>Hello,</h3>\
            <p>You will find the documentation you requested attached, thank you very much for your interest.</p>\
            <p>Best regards,</p>"
NOTIFICATION_HTML = \
            "<h3>Hi!</h3>\
            <p> {} has just downloaded the following document {}!</p>\
            <p>You can view detailed analytics here: <a href='{}'>{}</a></p>\
            <p>Keep crushing it!</p>\
            <p>WPCI Admin</p>"


class manageDocuments():

    document = None
    user = None
    signer_user = None
    google_credentials = None
    git_credentials = None
    link_id = None

    def __init__(self, doc_id=None):
        if doc_id:
            try:
                doc = Document.Document()
                self.document = doc.find_by_doc_id(doc_id)
                user = User.User()
                self.user = user.find_by_attr("org_id", self.document.org_id)
            except Exception as e:
                logger.info(F"[error renderPDF init] obtaining document from docid: {str(e)}")

    def is_valid_document(self):

        if self.document and self.user:
            return True

        else:
            return False

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

    def download_render_url_doc(self, pdf_url):
        """Downloads and renders pdf document from an external url"""

        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                file_full_path = tmpdir + "/" + pdf_url.split("/")[-1]
                file_tittle = file_full_path.split(".")[0]
                req = requests.get(pdf_url)
                if req.status == 200:
                    with open(file_full_path, 'wb') as mypdf:
                        mypdf.write(req.content)

                    pdffile = open(file_full_path, 'rb').read()
                    if not pdffile:
                        logger.info("Error rendering the pdf external document")
                        return None, None

                    return pdffile, file_tittle
                else:
                    logger.info("[Error] download_render_url_doc: couldnt download the pdf ")
                    return None, None

            except IOError as e:
                logger.info('pdf render IOError' + str(e))
                return None, None
            except Exception as e:
                logger.info("other error pdf render " + str(e))
                return None, None

    def download_render_sign_url_doc(self, pdf_url, timestamp_now, is_contract=False):
        """Downloads, renders and signs pdf document from an external url"""

        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                file_full_path = tmpdir + "/" + pdf_url.split("/")[-1]
                file_tittle = file_full_path.split(".")[0]
                watermark = "Document generated for: " + self.signer_user.email
                complete_hash = get_hash([timestamp_now, self.signer_user.email], [file_tittle])

                req = requests.get(pdf_url)
                if req.status == 200:
                    with open(file_full_path, 'wb') as mypdf:
                        mypdf.write(req.content)

                    if not req.content:
                        logger.info("Error rendering the pdf external document")
                        return None, None

                    if not is_contract:
                        pointa = fitz.Point(conf.AXIS_X, conf.AXIS_Y)
                        pointb = fitz.Point(conf.AXIS_X_LOWER, conf.AXIS_Y)
                        document = fitz.open(file_full_path)
                        for page in document:
                            page.insertText(pointa, text=watermark, fontsize=conf.WATERMARK_SIZE,
                                            fontname=conf.WATERMARK_FONT,
                                            rotate=conf.WATERMARK_ROTATION)
                            page.insertText(pointb, text="DocId: " + complete_hash, fontsize=conf.WATERMARK_SIZE,
                                            fontname=conf.WATERMARK_FONT, rotate=conf.WATERMARK_ROTATION)
                        document.save(file_full_path, incremental=1)
                        document.close()

                    pdffile = open(file_full_path, 'rb').read()
                    return pdffile, complete_hash, file_tittle
                else:
                    logger.info("[Error] download_render_url_doc: couldnt download the pdf ")
                    return None, None

            except IOError as e:
                logger.info('pdf render IOError' + str(e))
                return None, None
            except Exception as e:
                logger.info("other error pdf render " + str(e))
                return None, None

    def download_render_google_doc(self, pdf_id):
        """Downloads and renders pdf document from google"""
        # Load credentials from the session.
        credentials = google.oauth2.credentials.Credentials(
            **self.google_credentials
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
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

                pdffile = open(file_full_path, 'rb').read()
                if not pdffile:
                    logger.info("Error rendering google document")
                    return None, None

                return pdffile, file_tittle

            except IOError as e:
                logger.info('google render IOError' + str(e))
                return None, None
            except Exception as e:
                logger.info("other error google render " + str(e))
                return None, None

    def download_render_latex_doc(self, repo_url, main_tex="main.tex"):
        """Clones a repo and renders the file received as main_tex"""

        clone = F'git clone {repo_url}'
        rev_parse = 'git rev-parse master'

        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                subprocess.check_output(clone, shell=True, cwd=tmpdir)
                repo_name = os.listdir(tmpdir)[0]
                file_tittle = repo_name.strip(" ") + ".pdf"
                filesdir = os.path.join(tmpdir, repo_name)

                file_full_path = filesdir + "/" + main_tex.split(".")[0] + ".pdf"
                subprocess.check_output(rev_parse, shell=True, cwd=filesdir)
                subprocess.call(
                    F"texliveonfly --compiler=latexmk --arguments='-interaction=nonstopmode -pdf' -f {main_tex}",
                    shell=True,
                    cwd=filesdir
                )

                pdffile = open(file_full_path, 'rb').read()
                if not pdffile:
                    logger.info("Error rendering latex document")
                    return None, None

                return pdffile, file_tittle

            except IOError as e:
                logger.info('IOError' + str(e))
            except Exception as e:
                logger.info("other error" + str(e))

        return None, None

    def download_and_sign_google_doc(self, pdf_id, timestamp_now, is_contract=False):
        """Downloads, renders and signs a pdf google document"""
        MORPH = None
        watermark = "Document generated for: " + self.signer_user.email
        complete_hash = get_hash([timestamp_now, self.signer_user.email], [pdf_id])
        # Load credentials from the session.
        credentials = google.oauth2.credentials.Credentials(
            **self.google_credentials
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
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

                if not is_contract:
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
                logger.info('google render sign IOError' + str(e))
                return None, None, None
            except Exception as e:
                logger.info("other error google render sign" + str(e))
                return None, None, None

    def download_and_sign_latex_doc(self, repo_url, main_tex="main.tex", is_contract=False, options={}):
        """clones a repo, renders and signs a pdf latex document"""
        new_main_tex = "main2.tex"
        watermark = "Document generated for: " + self.signer_user.email

        clone = F'git clone {repo_url}'
        rev_parse = 'git rev-parse master'

        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                timestamp = str(time.time())
                subprocess.check_output(clone, shell=True, cwd=tmpdir)
                repo_name = os.listdir(tmpdir)[0]
                file_tittle = repo_name.strip(" ") + ".pdf"
                filesdir = os.path.join(tmpdir, repo_name)
                if options != {}:  # if there are special conditions to render
                    # modify the original template:
                    template = latex_jinja_env.get_template(filesdir + "/" + main_tex)
                    renderer_template = template.render(**options)
                    with open(filesdir + "/" + new_main_tex, "w") as f:  # saves tex_code to outpout file
                        f.write(renderer_template)
                else:
                    new_main_tex = main_tex

                file_full_path = filesdir + "/" + new_main_tex.split(".")[0] + ".pdf"
                run_git_rev_parse = subprocess.check_output(rev_parse, shell=True, cwd=filesdir)
                complete_hash = get_hash([timestamp, self.signer_user.email], [run_git_rev_parse.decode('UTF-8')])
                subprocess.call(
                    F"texliveonfly --compiler=latexmk --arguments='-interaction=nonstopmode -pdf' -f {new_main_tex}",
                    shell=True,
                    cwd=filesdir
                )

                if not is_contract:
                    pointa = fitz.Point(conf.AXIS_X, conf.AXIS_Y)
                    pointb = fitz.Point(conf.AXIS_X_LOWER, conf.AXIS_Y)
                    document = fitz.open(file_full_path)
                    for page in document:
                        page.insertText(pointa, text=watermark, fontsize=conf.WATERMARK_SIZE, fontname=conf.WATERMARK_FONT,
                                        rotate=conf.WATERMARK_ROTATION)
                        page.insertText(pointb, text="DocId: " + complete_hash, fontsize=conf.WATERMARK_SIZE,
                                        fontname=conf.WATERMARK_FONT, rotate=conf.WATERMARK_ROTATION)
                    document.save(file_full_path, incremental=1)
                    document.close()

                pdffile = open(file_full_path, 'rb').read()
                return pdffile, complete_hash, file_tittle

            except IOError as e:
                logger.info('IOError' + str(e))
                return None, None, None
            except Exception as e:
                logger.info("other error" + str(e))
                return None, None, None

    def render_document(self, main_tex, timestamp_now=None, sign=False):
        pdffile = None
        doc_type = getattr(self.document, "render", "")

        if doc_type == conf.GOOGLE:
            credentials_ok = self.set_google_credentials()
            if not credentials_ok:
                error = "Your google credentials are wrong"
                return None, None, None
            doc_google_id = get_id_from_url(self.document.doc_url)
            if sign:
                pdffile, complete_hash, file_tittle = self.download_and_sign_google_doc(
                    doc_google_id,
                    timestamp_now
                )
                return pdffile, complete_hash, file_tittle
            else:
                pdffile, file_tittle = self.download_render_google_doc(doc_google_id)
                return pdffile, None, file_tittle

        elif doc_type == conf.LATEX:
            if sign:
                pdffile, complete_hash, file_tittle = self.download_and_sign_latex_doc(
                    self.document.doc_url,
                    main_tex
                )
                return pdffile, complete_hash, file_tittle
            else:
                pdffile, file_tittle = self.download_render_latex_doc(self.document.doc_url, main_tex)
                return pdffile, None, file_tittle

        elif doc_type == conf.EXTERNAL:
            if sign:
                pdffile, complete_hash, file_tittle = self.download_render_sign_url_doc(
                    self.document.doc_url,
                    timestamp_now
                )
                return pdffile, complete_hash, file_tittle
            else:
                pdffile, file_tittle = self.download_render_url_doc(self.document.doc_url)
                return pdffile, None
        else:
            return None, None, None

    def render_contract(self, main_tex):
        error = ""
        CONTRACT_FILE_NAME = "document.pdf"
        pdf_file = None

        doc_type = getattr(self.document, "render", "")
        print("nosign")
        if doc_type == conf.GOOGLE:
            credentials_ok = self.set_google_credentials()
            if not credentials_ok:
                error = "Your google credentials are wrong"
                return None, error
            doc_google_id = get_id_from_url(self.document.contract_url)
            pdffile, file_tittle = self.download_render_google_doc(doc_google_id)
            return pdffile, error

        elif doc_type == conf.LATEX:
            pdffile, file_tittle = self.download_render_latex_doc(self.document.contract_url, main_tex)
            return pdffile, error

        elif doc_type == conf.EXTERNAL:
            pdffile, file_tittle = self.download_render_url_doc(self.document.contract_url)
            return pdffile, error
        else:
            return None, None

    def render_and_sign_contract(self, main_tex, timestamp_now, b64_pdf=None):
        error = ""
        CONTRACT_FILE_NAME = "document.pdf"
        pdf_file = contract_b2chainized = sign_record = None

        doc_type = getattr(self.document, "render", "")
        if b64_pdf is None:
            print("pdf is none")
            if doc_type == conf.GOOGLE:
                credentials_ok = self.set_google_credentials()
                if not credentials_ok:
                    error = "Your google credentials are wrong"
                    return None, None, error
                doc_google_id = get_id_from_url(self.document.contract_url)

                pdf_file, complete_hash, file_tittle = self.download_and_sign_google_doc(
                    doc_google_id,
                    timestamp_now,
                    is_contract=True
                )
            elif doc_type == conf.LATEX:
                pdf_file, complete_hash, file_tittle = self.download_and_sign_latex_doc(
                    self.document.contract_url,
                    main_tex,
                    is_contract=True
                )

            elif doc_type == conf.EXTERNAL:
                pdf_file, complete_hash, file_tittle = self.download_render_sign_url_doc(
                    self.document.contract_url,
                    timestamp_now,
                    is_contract=True
                )

            b64_pdf = self.convert_bytes_to_b64(pdf_file)

        # Check if the b64 file exists after its rendering
        if b64_pdf is None:
            error = "[Error render_contract] couldn't convert to b64"
            logger.error(error)
            return None, sign_record, error

        try:
            crypto_tool = CryptoTools()
            if self.user.org_logo is None or self.user.org_logo == "":
                org_logo = open(conf.DEFAULT_LOGO_PATH, 'r').read()
            else:
                org_logo = self.user.org_logo

            sign_document_hash(self.signer_user, b64_pdf)
            rsa_object = crypto_tool.import_RSA_string(self.signer_user.priv_key)
            pub_key_hex = crypto_tool.savify_key(rsa_object.publickey()).decode("utf-8")

            crypto_sign_payload = {
                "pdf": b64_pdf,
                "timezone": conf.TIMEZONE,
                "signature": self.signer_user.sign,
                "signatories": [
                    {
                        "email": self.signer_user.email,
                        "name": self.signer_user.name,
                        "public_key": pub_key_hex
                    }],
                "params": {
                    "locale": conf.LANGUAGE,
                    "title": self.user.org_name + " contract",
                    "file_name": CONTRACT_FILE_NAME,
                    "logo": org_logo,
                }
            }

            contract_b2chainized, sign_record = get_b2h_document(crypto_sign_payload, self.signer_user)

            if not contract_b2chainized:
                error = "Failed loading contract"
                logger.error(error)
                return None, None, error

        except Exception as e:
            logger.info("Error rendering contract: {}".format(str(e)))
        finally:
            return contract_b2chainized, sign_record, error

    @gen.engine
    def render_and_send_all_documents(self, email, name, email_body_html, timestamp_now,
                                      contract_file_name, doc_file_name, contract_b64_file=None,
                                      main_tex="main.tex", email_body_text=""):
        """ Trigger the renderization of the documents/contracts related to this doc object """
        ATTACH_CONTENT_TYPE = 'octet-stream'
        render_doc = False
        attachment_list = []
        render_contract = False
        error = ""

        self.signer_user = signerUser.SignerUser(email, name)
        # create the signer user so it can generate their keys
        self.signer_user.create()

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
                    try:
                        print("start rend doc")
                        doc_file_path = os.path.join(tmp_dir, conf.DOC_FILE_NAME)
                        print("ag")
                        pdf_file, complete_hash, file_tittle = self.render_document(
                            main_tex,
                            timestamp_now,
                            sign=True
                        )
                        print("pdf done", complete_hash)
                        if pdf_file:
                            with open(doc_file_path, 'wb') as temp_file:
                                temp_file.write(pdf_file)

                            print("upload to s3")

                            uploaded_document_url = upload_to_s3(doc_file_path, doc_file_name)
                            self.signer_user.s3_doc_url = S3_BASE_URL.format(doc_file_name)
                            self.signer_user.update()
                            # this is the payload for the white paper file
                            doc_attachment = dict(file_type=ATTACH_CONTENT_TYPE,
                                                  file_path=doc_file_path,
                                                  filename=conf.DOC_FILE_NAME)
                            attachment_list.append(doc_attachment)
                        else:
                            error = F"Couldn't render and attach the doc: {doc_file_name}"
                            logger.error(F"[ERROR render_and_send_all_documents render_doc] Couldn't render the pdf")

                    except Exception as e:
                        logger.error(F"[ERROR render_and_send_all_documents] {e}")
                        error = "couldn't render the document {doc_file_name}"

                if render_contract:
                    print("start rend contr")
                    contract_file_path = os.path.join(tmp_dir, conf.CONTRACT_FILE_NAME)
                    print("contrrr")
                    contract_b2chainized, sign_record, error = self.render_and_sign_contract(
                        main_tex,
                        timestamp_now,
                        contract_b64_file
                    )

                    print("pdf done c", sign_record)
                    if contract_b2chainized:
                        with open(contract_file_path, 'wb') as temp_file:
                            temp_file.write(contract_b2chainized)

                        print("upload to s3")

                        sign_record.s3_contract_url = S3_BASE_URL.format(contract_file_name)
                        sign_record.link_id = self.link_id
                        sign_record.update()

                        uploaded_document_url = upload_to_s3(contract_file_path, contract_file_name)
                        self.signer_user.s3_doc_url = S3_BASE_URL.format(contract_file_name)
                        self.signer_user.update()
                        # this is the payload for the white paper file
                        doc_attachment = dict(file_type=ATTACH_CONTENT_TYPE,
                                              file_path=contract_file_path,
                                              filename=conf.CONTRACT_FILE_NAME)
                        attachment_list.append(doc_attachment)

                    else:
                        error = error + F" Couldn't render and attach the contract: {contract_file_name}"
                        logger.error(F"[ERROR render_and_send_all_documents render_contract] Couldn't render the pdf")

                if len(attachment_list) > 0 and error == "":
                    self.send_attachments(attachment_list, email_body_html, email_body_text)
                else:
                    logger.error(error)

            except Exception as e:
                logger.info("error rendering all documents: {}".format(str(e)))
                error = "error rendering all documents"
            finally:
                logger.info("documents rendering has finished")

    def render_main_document(self, main_tex="main.tex"):
        """ Trigger the renderization of the documents/contracts related to this doc object """
        pdf_rendered = None
        error = ""

        with tempfile.TemporaryDirectory() as tmp_dir:

            try:
                # Check which of the documents are going to be rendered
                if self.document.type == conf.CONTRACT or self.document.type == conf.NDA:
                    render_contract = True
                    render_doc = False
                else:
                    render_doc = True
                    render_contract = False

                if render_doc:
                    try:
                        pdf_file, complete_hash, file_tittle = self.render_document(main_tex, sign=False)
                        if not pdf_file:
                            logger.error(F"[ERROR render_main_document render_doc] Couldn't render the pdf")
                            return None
                        pdf_rendered = pdf_file

                    except Exception as e:
                        logger.error(F"[ERROR render_main_document doc] {e}")

                if render_contract:
                    try:
                        contract_rendered, error = self.render_contract(main_tex)
                        if not contract_rendered:
                            logger.error(F"[ERROR render_main_document render_contract] Couldn't render the pdf")
                            return None
                        pdf_rendered = contract_rendered
                    except Exception as e:
                        logger.error(F"[ERROR render_main_document contract] {e}")

            except Exception as e:
                logger.info("[error] rendering main document: {}".format(str(e)))
            finally:
                logger.info("documents rendering has finished")
                return pdf_rendered

    def send_attachments(self, attachment_list, email_body_html, email_body_text):
        """Send a list of attachments to the signer and organization"""
        BASE_PATH = "/docs/"
        mymail = Mailer(username=conf.SMTP_USER, password=conf.SMTP_PASS, host=conf.SMTP_ADDRESS, port=conf.SMTP_PORT)

        if not email_body_html:
            email_body_html = DEFAULT_HTML_TEXT

        # send the email with the result attachments
        sender_format = "{} <{}>"
        loader = Loader("templates/email")
        button = loader.load("cta_button.html")
        notification_subject = F"Your Document {self.document.doc_id} has been downloaded"
        analytics_link = F"{conf.BASE_URL}{BASE_PATH}analytics/{self.document.doc_id}"

        mymail.send(subject=self.document.doc_name,
                    email_from=sender_format.format(self.user.org_name, conf.SMTP_EMAIL),
                    emails_to=[self.signer_user.email],
                    attachments_list=attachment_list,
                    html_message=email_body_html + button.generate().decode("utf-8"),
                    text_message=email_body_text)

        html_text = NOTIFICATION_HTML.format(self.signer_user.email, self.document.doc_id, analytics_link,
                                             analytics_link)
        mymail.send(subject=notification_subject,
                    attachments_list=attachment_list,
                    email_from=sender_format.format("WPCI Admin", conf.SMTP_EMAIL),
                    emails_to=[self.user.org_email], html_message=html_text,
                    text_message=email_body_text)

    def convert_bytes_to_b64(self, pdf_file):
        '''Call the render function and retrive a base 64 pdf'''
        b64_pdf = None

        try:

            with tempfile.TemporaryDirectory() as tmpdir:
                file_full_path64 = os.path.join(tmpdir, "temp_b64_file.base64")
                with open(file_full_path64, 'wb') as ftemp:
                    # write in a new file the base64
                    ftemp.write(base64.b64encode(pdf_file))

                b64_pdf = open(file_full_path64, 'r').read()

        except Exception as e:
            logger.info("[Error] convert_bytes_to_b64 " + str(e))

        return b64_pdf
