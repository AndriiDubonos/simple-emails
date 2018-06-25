import re
from smtplib import *
import asyncio
import os
from functools import partial
from email.mime.multipart import MIMEMultipart
from email.message import EmailMessage
from functools import wraps
from threading import Thread
from .email import HTMLEmail


class Base(HTMLEmail):
    # def __init__(self, recipients, sender, login, password, smtp_server=None,
    #              smt_port=None):
    #     self.context = {}
    #     if isinstance(recipients, (tuple, list, set, frozenset)):
    #         self.recipients = list(recipients)
    #     elif isinstance(recipients, str):
    #         self.recipients = [recipients]
    #     else:
    #         raise AttributeError('recipients should be iterable type or '
    #                              'string got {} type'.format(type(recipients).
    #                                                          __name__))
    #     self.sender = sender
    #     self.login = login
    #     self.password = password
    #     self.subject = "Testing asynchronous sending email"
    #     self.html_template = None
    #     self.plain_text_template = None
    #     self.smtp_server = smtp_server
    #     self.smtp_port = smt_port

    def set_smtp_server(self, smtp_server, smtp_port=None):
        self.smtp_server = smtp_server
        if smtp_port:
            self.smtp_port = smtp_port

    def _prepare_message(self, subject, html_template, context):
        print("###########################################################",os\
            .path.join(os.path.abspath(os.curdir), 'templates'))
        try:
            from jinja2 import Environment, FileSystemLoader
            body = Environment(loader=FileSystemLoader(os.path.join(
                os.path.abspath(os.curdir),
                'templates'))).get_or_select_template(
                html_template).render(
                **context)
        except ImportError as e:
            print('{}: {}'.format(e.__class__.__name__, e))
            with open(html_template, 'rt') as template:
                body = template.read()
        msg = EmailMessage()
        msg.set_content(body)
        msg['Subject'] = subject
        msg['From'] = self.from_email
        msg['To'] = self.to

        ssl = SMTP()
        # ssl.starttls()
        # ssl.connect()
        # ssl.ehlo_or_helo_if_needed()
        # ssl.login(self.login, self.password)
        ssl.set_debuglevel(True)
        return ssl, msg

    def start_email_worker(self, loop):
        asyncio.set_event_loop(loop)
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            asyncio.gather(*asyncio.Task.all_tasks()).cancel()
            loop.stop()
            loop.close()
    #
    # def _async_send(self, subject, template, context):
    #

    def _sync_send(self, subject, template, context):
        ssl, msg = self._prepare_message(subject, template, context)
        # ssl.sendmail(self.from_email, self.to, msg.as_string())
        # ssl.quit()
        print(msg)
    def send_mail(self, *args, **kwargs):
        # if async:
        #     worker_loop = asyncio.new_event_loop()
        #     worker = Thread(target=self.start_email_worker, args=(worker_loop,))
        #     worker.start()
        #     worker_loop.call_soon_threadsafe(self._sync_send, self.subject,
        #                                      self.html_template, self.context)
        # else:
        self.context = kwargs
        self._sync_send(self.subject, self.html_template, self.context)



    def get_message_context(self):
        return self.context
