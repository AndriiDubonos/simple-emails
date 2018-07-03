from django.views.generic.base import View
from django.http import HttpResponse
from .simple_email import SimpleEmailHandler, Register, get_email_class


mail = get_email_class()


@Register.register_text('test')
@Register.register_html("test")
class ResetPassword(mail):
    subject = "Re:"
    from_email = "Self test"
    html_template = 'test.html'
    message_template = 'text.txt'


class Index(View):
    def dispatch(self, request, *args, **kwargs):
        SimpleEmailHandler.handle('test', test='TEST', #async=True,
                                  user='Denizantip',
                                  to='denis.mih@computools.com')
        return HttpResponse('Hello World!')
