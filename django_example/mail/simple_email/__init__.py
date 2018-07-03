from .register import Register, SimpleEmailHandler
import inspect


def get_send_meth():
    from .email import HTMLEmail
    glob = inspect.stack()[1][0].f_globals
    framework = glob.get("Flask")
    if framework:
        print("choosed: ", framework)
        for value in glob.values():
            if isinstance(value, framework):
                app = value
                from .flask_email import Flask_mail
                return Flask_mail
    try:
        import django.apps as apps
        if apps.apps.loading:
            print("choosed: Django")
            from .django_mail import Django_mail
            return Django_mail
    except ImportError as e:
        print(e)
    print("choosed: base")
    from .base_mail import Base
    return Base
