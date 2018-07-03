from flask import Flask
from simple_email import SimpleEmailHandler, Register, get_email_class


app = Flask(__name__)
app.config.from_object('config')
Mail = get_email_class()


@Register.register_text('test')
@Register.register_html('test')
class ResetPassword(Mail):
    subject = 'Re:'
    from_email = 'Self_test'
    html_template = 'test.html'
    message_template = 'text.txt'


@app.route('/')
def hello_world():
    SimpleEmailHandler.handle('test', test='test', user='Denizantip@gmail.com',
                              to='denis.mih@computools.com',
                              password="vrreeigzelljnogk",
                              host='smtp.gmail.com', port='587', tls=True)
    return 'Hello World!', 200


if __name__ == '__main__':
    app.config.from_pyfile('config.py')
    app.run()
