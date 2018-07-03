import abc
# from simple_email.register import Register

# print(Register)
class HTMLEmail(abc.ABC):
    def __init__(self):
        self._subject = None
        self._from_email = None
        self._to = None

    @property
    @abc.abstractmethod
    def subject(self):
        return self._subject

    @subject.setter
    @abc.abstractmethod
    def subject(self, val):
        if isinstance(val, str):
            self._subject = val
        else:
            raise TypeError('from_email must be str type, got {} '
                            'type'.format(type(val).__name__))

    @property
    @abc.abstractmethod
    def from_email(self):
        return self._from_email

    @from_email.setter
    @abc.abstractmethod
    def from_email(self, val):
        if isinstance(val, str):
            self._from_email = val
        else:
            raise TypeError('from_email must be str type, got {} '
                            'type'.format(type(val).__name__))

    # @property
    # @abc.abstractmethod
    # def to(self):
    #     return self._to
    #
    # @to.setter
    # @abc.abstractmethod
    # def to(self, val):
    #     if isinstance(val, (list, tuple)):
    #         self._to = val
    #     else:
    #         raise TypeError('from_email must be list or tuple type, got {} '
    #                         'type'.format(type(val).__name__))
    # @abc.abstractmethod
    def thread_send(self, to, **kwargs):
        pass

    # @abc.abstractmethod
    def get_message(self, to, **kwargs):
        pass

    # @abc.abstractmethod
    def sync_send(self, to, **kwargs):
        pass

    # @abc.abstractmethod
    def async_send(self, to, **kwargs):
        pass

    def get_context(self):
        return self.context


