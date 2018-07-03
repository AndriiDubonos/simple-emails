from .register import Register, SimpleEmailHandler
import inspect


def get_email_class():
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
        from django import get_version
        import django.apps as apps
        if apps.apps.loading:
            print("choosed: django v{}".format(get_version()))
            from .django_mail import Django_mail
            return Django_mail
    except ImportError as e:
        print(e)
    print("choosed: base")
    from .base_mail import Base
    return Base
