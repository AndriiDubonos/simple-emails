from django.views.generic.base import View
from django.http import HttpResponse
from .simple_email import SimpleEmailHandler, Register, get_send_meth

mail = get_send_meth()
print(mail)
@Register.register_text('test')
@Register.register_html("test")
class ResetPassword(mail):
    subject = "Re:"
    from_email = "Self test"
    to = ["Denizantip@gmail.com"]
    html_template = 'test.html'
    message_template = 'text.txt'



class Index(View):
    def dispatch(self, request, *args, **kwargs):
        SimpleEmailHandler.handle('test', test='TEST', user='Denizantip')
        return HttpResponse('Hello World')