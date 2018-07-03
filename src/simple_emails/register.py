# __all__ = ["Register"]
import reprlib
from itertools import chain
from .email import HTMLEmail
from collections.abc import Iterable


class InstanceException(Exception):
    pass


class _SingletonRegisterMeta(type):
    _instances = {}
    _map = {"text": {},
            "html": {}}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super().__call__(*args, **kwargs)
        return cls._instances[cls]

    def register_text(cls, key):
        if not key:
            raise AttributeError("Key required")

        def wrapper(klass):
            if HTMLEmail not in klass.mro():
                raise InstanceException("Class not instantiiate from base "
                                        "HTMLEmail class")
            if not hasattr(klass, 'message_template'):
                raise AttributeError("In register class must be provided "
                                     "message_template attribute")
            cls._map["text"].update({key + "_text": klass})
            return klass

        return wrapper

    def register_html(cls, key):
        if not key:
            raise AttributeError("Key required")

        def wrapper(klass):
            if HTMLEmail not in klass.mro():
                raise InstanceException("Class not instantiiate from base "
                                        "HTMLEmail class")
            if not hasattr(klass, 'html_template'):
                raise AttributeError("In register class must be provided "
                                     "html_template attribute")
            cls._map["html"].update({key + "_html": klass})
            return klass

        return wrapper

    def unregister_text(cls, text):
        try:
            del cls._map["text"][text]
        except KeyError:
            pass

    def unregister_html(cls, html):
        try:
            del cls._map['html'][html]
        except KeyError:
            pass

    def unregister_all(cls, key):
        if isinstance(key, str):
            try:
                del cls._map['text'][key]
            except KeyError:
                try:
                    del cls._map['html'][key]
                except KeyError:
                    pass
        elif isinstance(key, object):
            values = list(cls._map['text'].values())
            values.extend(list(cls._map['html'].values()))
            if key in values:
                cls._map["text"] = {k: v for k, v in cls._map['text'].items()
                                    if v
                                    != key}
                cls._map["html"] = {k: v for k, v in cls._map['html'].items()
                                    if v
                                    != key}

    def items(cls):
        return tuple(chain(cls._map['html'].items(), cls._map['text'].items()))

    def __iter__(cls):
        return chain(cls._map['html'].values(), cls._map['text'].values())

    def __getitem__(cls, item):
        text = cls._map['text'].get(item + "_text")
        html = cls._map['html'].get(item + "_html")
        if (text and html) and (text is not html):
            return {"text": text, 'html': html}
        else:
            return text or html

    def __len__(cls):
        return sum((len(cls._map['text']), len(cls._map['html'])))

    def __repr__(cls):
        r = reprlib.Repr()
        r.maxdict = 3
        return 'registerded_text -> {}\n' 'registered_html -> {}'.format(
            r.repr(cls._map['text']), r.repr(cls._map['html']))


class Register(metaclass=_SingletonRegisterMeta):
    pass


class SimpleEmailHandler:
    @classmethod
    def handle(cls, name, **kwargs):
        to = kwargs.pop('to', None)
        if isinstance(to, str):
            to = [to]
        elif isinstance(to, Iterable):
            pass
        else:
            raise TypeError(
                '"to" must by str or Iterable type. Got {} type'.format(
                    type(to).__name__))
        async = kwargs.pop("async", False)
        thread = kwargs.pop('threaded', False)
        mail_cls = Register[name]()
        if async:
            thread = False
            return mail_cls.async_send(to, **kwargs)
        elif thread:
            return mail_cls.thread_send(to, **kwargs)
        else:
            return mail_cls.sync_send(to, **kwargs)
