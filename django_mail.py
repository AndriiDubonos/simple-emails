from .email import HTMLEmail
from django.conf import settings
from django.core.mail import EmailMultiAlternatives as Message
from django.utils.module_loading import import_string

from django.template.backends.base import get_app_template_dirs
from django.template.engine import Engine, Context
from django.template.loader import render_to_string
from django.utils.html import strip_tags


class Django_mail(HTMLEmail):
    def __init__(self, backend=None, **kwargs):
        self.connection = import_string(backend or settings.EMAIL_BACKEND)(
            **kwargs)
        super().__init__()

    def send_mail(self, *args, **kwargs):
        html_message = None
        text_message = None
        self.context = Context(kwargs)
        try:
            engine = Engine(dirs=settings.TEMPLATE_DIRS)
        except AttributeError:
            engine = Engine(dirs=get_app_template_dirs("templates"))

        if hasattr(self, 'html_template'):
            html_message = engine.get_template(self.html_template).render(
                self.context)
        if hasattr(self, 'message_template'):
            text_message = render_to_string(self.message_template, kwargs)

        if html_message and not text_message:
            text_message = strip_tags(html_message).strip()

        mail = Message(self.subject, text_message, self.from_email,
                       self.to,
                       connection=self.connection)

        if html_message:
            mail.attach_alternative(html_message, 'text/html')
        return mail.send()
