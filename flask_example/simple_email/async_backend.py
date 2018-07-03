from django.conf import settings
from django.core.mail.backends.base import BaseEmailBackend
from .async_mail import SMTP


class AsyncEmailBackend(BaseEmailBackend):
    async def send_messages(self, email_messages):
        for msg in email_messages:
            smtp = SMTP(use_tls=settings.EMAIL_USE_TLS,
                        hostname=settings.EMAIL_HOST, port=settings.EMAIL_PORT)
            await smtp.connect()
            await smtp._ehlo_or_helo_if_needed()
            if not settings.EMAIL_USE_TLS:
                await smtp.starttls()
            if settings.EMAIL_HOST_USER and settings.EMAIL_HOST_PASSWORD:
                await smtp.auth_login(settings.EMAIL_HOST_USER,
                                    settings.EMAIL_HOST_PASSWORD)
            send_coro = smtp.send_message(msg.message(), timeout=None)
            await send_coro
            await smtp.quit()
