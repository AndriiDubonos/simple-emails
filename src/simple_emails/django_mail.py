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

    def get_message(self, to, **kwargs):
        html_message = None
        text_message = None
        context = Context(kwargs)
        try:
            engine = Engine(dirs=settings.TEMPLATE_DIRS)
        except AttributeError:
            engine = Engine(dirs=get_app_template_dirs("templates"))

        if hasattr(self, 'html_template'):
            html_message = engine.get_template(self.html_template).render(
                context)
        if hasattr(self, 'message_template'):
            text_message = render_to_string(self.message_template, kwargs)

        if html_message and not text_message:
            text_message = strip_tags(html_message).strip()
        #
        # mail = Message(text_message)
        # mail['From'] = settings.EMAIL_DEFAULT_SENDER
        # mail['To'] = to
        # mail['Subject'] = "Hello async shit!!!!"
        mail = Message(self.subject, text_message, self.from_email, to,
                       connection=self.connection)
        if html_message:
            mail.attach_alternative(html_message, 'text/html')
        return mail

    def sync_send(self, to, **kwargs):
        print("SYNC")
        from .async_backend import AsyncEmailBackend
        import asyncio
        msg = self.get_message(to=to, **kwargs)
        if isinstance(msg.connection, AsyncEmailBackend):
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(msg.send())
            return
        return msg.send()

    def async_send(self, to, **kwargs):
        print("ASYNC")
        from .async_mail import SMTP
        import asyncio
        msg = self.get_message(to=to, **kwargs).message()
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        smtp = SMTP(use_tls=settings.EMAIL_USE_TLS,
                    hostname=settings.EMAIL_HOST, port=settings.EMAIL_PORT,
                    loop=loop)
        print('smtp created')
        loop.run_until_complete(smtp.connect())
        print("trying to connect...")
        loop.run_until_complete(smtp._ehlo_or_helo_if_needed())
        if not settings.EMAIL_USE_TLS:
            loop.run_until_complete(smtp.starttls())
        print('-' * 79 + '\nmust be connected')
        if settings.EMAIL_HOST_USER and settings.EMAIL_HOST_PASSWORD:
            loop.run_until_complete(smtp.auth_login(settings.EMAIL_HOST_USER,
                                                    settings.EMAIL_HOST_PASSWORD))
        print('Auth passed')
        send_coro = smtp.send_message(msg, timeout=None)
        loop.run_until_complete(send_coro)
        loop.run_until_complete(smtp.quit())
        print('Finished')
        loop.close()

    def thread_send(self, to, **kwargs):
        print("THREAD")
        import threading
        msg = self.get_message(to=to, **kwargs)
        return threading.Thread(target=msg.send)
