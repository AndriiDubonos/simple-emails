from .register import Register, SimpleEmailHandler
import inspect


def get_email_class():
    from .email import HTMLEmail
    glob = inspect.stack()[1][0].f_globals
    framework = glob.get("Flask")
    if framework:
        print("choosed: ", framework)
        try:
            import flask_mail
            for value in glob.values():
                if isinstance(value, framework):
                    app = value
                    from .flask_email import Flask_mail
                    return Flask_mail
        except ImportError:
            print("Flask-mail not found switch to Base")
            from .base_mail import Base
            return Base
    try:
        from django import get_version
        import django.apps as apps
        if apps.apps.loading:
            print("choosed: Django v{}".format(get_version()))
            from .django_mail import Django_mail
            return Django_mail
    except ImportError as e:
        print(e)
    print("choosed: base")
    from .base_mail import Base
    return Base

