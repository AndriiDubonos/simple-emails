from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from .email import HTMLEmail
import os
import xml
import smtplib


def remove_html_tags(text):
    return ''.join(xml.etree.ElementTree.fromstring(text).itertext())


class Base(HTMLEmail):
    def get_message(self, to, **kwargs):
        msg = MIMEMultipart('alternative')
        try:
            from jinja2 import Environment, FileSystemLoader
            def rendering(templ):
                return Environment(loader=FileSystemLoader(
                    os.path.join(
                        os.path.abspath(os.curdir),
                        'templates'))).get_or_select_template(
                    templ).render(
                    **kwargs)

            if hasattr(self, "html_template"):
                html = rendering(self.html_template)
            if hasattr(self, "message_template"):
                text = rendering(self.message_template)
        except ImportError as e:
            print('{}: {}'.format(e.__class__.__name__, e))
            with open(self.html_template, 'rt') as template:
                text = remove_html_tags(template.read())
        html_msg = MIMEText(html, "html")
        text_msg = MIMEText(text, "plain")
        msg.attach(text_msg)
        msg.attach(html_msg)
        msg['Subject'] = self.subject
        msg['From'] = self.from_email
        # msg['To'] = to
        return msg

    def async_send(self, to, **kwargs):
        pass

    def sync_send(self, to, **kwargs):
        host = kwargs["host"]
        port = kwargs["port"]
        s = smtplib.SMTP() if kwargs['tls'] else smtplib.SMTP_SSL()
        s.connect(host, port)
        if kwargs['tls']:
            s.starttls()
        if 'user' and 'password' in kwargs.keys():
            s.login(kwargs['user'], kwargs['password'])
        msg = self.get_message(to, **kwargs)
        s.send_message(msg, to_addrs=to)
        s.quit()

    def thread_send(self, to, **kwargs):
        pass
