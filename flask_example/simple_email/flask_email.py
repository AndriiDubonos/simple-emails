from .email import HTMLEmail
import os
from flask_mail import Mail, Message
from flask import render_template, render_template_string
from flask import current_app


class Flask_mail(HTMLEmail):
    def sync_send(self, to, **kwargs):
        test = True
        self.context = kwargs
        mail = Mail(current_app)
        msg = Message(subject=self.subject, recipients=self.to,
                      sender=self.from_email)
        if hasattr(self, 'html_template'):
            msg.html = render_template(self.html_template, **self.context)
        if hasattr(self, 'message_template'):
            with open(os.path.join(current_app.template_folder,
                             self.message_template)) as txt_template:
                msg.body = render_template_string(txt_template.read(),
                                                  **self.context)
        if test:
            with mail.record_messages():
                print(msg)
                print("is Message has send method: ", hasattr(msg, 'send'))
        else:
            mail.send(msg)
