import asyncio
import socket
import ssl
import re
import base64
import hmac
import copy
from email.utils import parseaddr, formataddr, getaddresses
from email.generator import Generator
from typing import NamedTuple
from io import StringIO
from asyncio.sslproto import SSLProtocol

MAX_LINE_LENGTH = 8192
SMTP_PORT = 25
SMTP_TLS_PORT = 465
DEFAULT_TIMEOUT = 60
LINE_ENDINGS_REGEX = re.compile(b'(?:\r\n|\n|\r(?!\n))')
PERIOD_REGEX = re.compile(b'(?m)^\.')

SMTPResponse = NamedTuple('SMTPResponse', [('code', int), ('message', str)])


def quote_address(address):
    display_name, parsed_address = parseaddr(address)
    if parsed_address:
        quoted_address = '<{}>'.format(parsed_address)
    else:
        quoted_address = '<{}>'.format(address.strip())

    return quoted_address


def crammd5_verify(username, password, challenge):
    decoded_challenge = base64.b64decode(challenge)
    md5_digest = hmac.new(password, msg=decoded_challenge, digestmod='md5')
    verification = username + b' ' + md5_digest.hexdigest().encode('ascii')
    encoded_verification = base64.b64encode(verification)

    return encoded_verification


class SMTPProtocol(asyncio.StreamReaderProtocol):
    def __init__(self, reader, loop=None):
        self._stream_reader = None
        self._stream_writer = None
        self._loop = loop or asyncio.get_event_loop()

        super().__init__(
            reader, client_connected_cb=self.on_connect, loop=self._loop)

        self._io_lock = asyncio.Lock(loop=self._loop)

    def on_connect(self, reader, writer):
        self._stream_reader = reader
        self._stream_writer = writer

    def connection_made(self, transport):
        self._stream_reader._transport = transport
        self._over_ssl = transport.get_extra_info('sslcontext') is not None
        if self._client_connected_cb is not None:
            self._stream_writer = asyncio.StreamWriter(
                transport, self, self._stream_reader, self._loop)
            res = self._client_connected_cb(
                self._stream_reader, self._stream_writer)
            if asyncio.iscoroutine(res):
                self._loop.create_task(res)

    def upgrade_transport(self, context, server_hostname, waiter):
        assert not self._over_ssl, 'Already using TLS'

        if self._stream_reader is None or self._stream_writer is None:
            raise Exception('Client not connected')

        transport = self._stream_reader._transport

        tls_protocol = SSLProtocol(
            self._loop, self, context, waiter, server_side=False,
            server_hostname=server_hostname)

        app_transport = tls_protocol._app_transport

        if hasattr(transport, 'set_protocol'):
            transport.set_protocol(tls_protocol)
        else:
            transport._protocol = tls_protocol

        self._stream_reader._transport = app_transport
        self._stream_writer._transport = app_transport

        tls_protocol.connection_made(transport)
        self._over_ssl = True

        return tls_protocol

    async def read_response(self, timeout=None):
        if self._stream_reader is None:
            raise Exception('Client not connected')

        code = None
        response_lines = []

        while True:
            async with self._io_lock:
                line = await self._readline(timeout=timeout)
            try:
                code = int(line[:3])
            except ValueError:
                pass

            message = line[4:].strip(b' \t\r\n').decode('ascii')
            response_lines.append(message)

            if line[3:4] != b'-':
                break

        full_message = '\n'.join(response_lines)

        if code is None:
            raise Exception('Malformed SMTP response: {}'.format(full_message))

        return SMTPResponse(code, full_message)

    async def write_and_drain(self, data, timeout):
        if self._stream_writer is None:
            raise Exception('Client not connected')

        self._stream_writer.write(data)

        async with self._io_lock:
            await self._drain_writer(timeout)

    async def write_message_data(self, data, timeout):
        data = LINE_ENDINGS_REGEX.sub(b'\r\n', data)
        data = PERIOD_REGEX.sub(b'..', data)
        if not data.endswith(b'\r\n'):
            data += b'\r\n'
        data += b'.\r\n'

        await self.write_and_drain(data, timeout=timeout)

    async def execute_command(self, *args, timeout):
        command = b' '.join(args) + b'\r\n'

        await self.write_and_drain(command, timeout=timeout)
        response = await self.read_response(timeout=timeout)

        return response

    async def starttls(self, tls_context, server_hostname=None,
                       timeout=0):
        if self._stream_writer is None:
            raise Exception('Client not connected')

        response = await self.execute_command(b'STARTTLS', timeout=timeout)

        if response.code != 220:
            raise Exception(response.code, response.message)

        await self._drain_writer(timeout)

        waiter = asyncio.Future(loop=self._loop)

        tls_protocol = self.upgrade_transport(
            tls_context, server_hostname=server_hostname, waiter=waiter)

        try:
            await asyncio.wait_for(waiter, timeout=timeout, loop=self._loop)
        except asyncio.TimeoutError as exc:
            raise Exception(str(exc))

        return response, tls_protocol

    async def _drain_writer(self, timeout=0):
        if self._stream_writer is None:
            raise Exception('Client not connected')

        drain_task = asyncio.Task(self._stream_writer.drain(), loop=self._loop)
        try:
            await asyncio.wait_for(drain_task, timeout, loop=self._loop)
        except ConnectionError as exc:
            raise Exception(str(exc))
        except asyncio.TimeoutError as exc:
            raise Exception(str(exc))

    async def _readline(self, timeout=None):
        read_task = asyncio.Task(
            self._stream_reader.readuntil(separator=b'\n'), loop=self._loop)
        try:
            line = await asyncio.wait_for(
                read_task, timeout, loop=self._loop)
        except ConnectionError as exc:
            raise Exception(str(exc))
        except asyncio.LimitOverrunError:
            raise Exception(500, 'Line too long.')
        except asyncio.TimeoutError as exc:
            raise Exception(exc)
        except asyncio.IncompleteReadError as exc:
            if exc.partial == b'':

                raise Exception('Unexpected EOF received', exc)
            else:

                self._stream_writer.close()
                line = exc.partial

        return line


class SMTPConnection:
    def __init__(
            self, hostname,
            port,
            local_hostname=None,
            timeout=None,
            loop=None,
            use_tls=None,
            validate_certs=None,
            certfile=None,
            keyfile=None,
            tls_context=None,
            cert_bundle=None):
        self.protocol = None
        self.transport = None

        if tls_context is not None and certfile is not None:
            raise ValueError(
                'Either a TLS context or a certificate/key must be provided')

        self.hostname = hostname
        self.port = port
        self.timeout = timeout
        self.use_tls = use_tls
        self._source_address = local_hostname
        self.validate_certs = validate_certs
        self.client_cert = certfile
        self.client_key = keyfile
        self.tls_context = tls_context
        self.cert_bundle = cert_bundle

        self.loop = loop or asyncio.get_event_loop()
        self._connect_lock = asyncio.Lock(loop=self.loop)

    @property
    def is_connected(self):
        return bool(self.transport and not self.transport.is_closing())

    @property
    def source_address(self):
        if self._source_address is None:
            self._source_address = socket.getfqdn()

        return self._source_address

    async def connect(
            self,
            hostname=None,
            port=None,
            source_address=None,
            timeout=None,
            loop=None,
            use_tls=None, validate_certs=None,
            certfile=None,
            keyfile=None,
            tls_context=None,
            cert_bundle=None):

        await self._connect_lock.acquire()

        if hostname is not None:
            self.hostname = hostname
        if loop is not None:
            self.loop = loop
        if use_tls is not None:
            self.use_tls = use_tls
        if validate_certs is not None:
            self.validate_certs = validate_certs

        if port is not None:
            self.port = port

        if self.port is None:
            self.port = SMTP_TLS_PORT if self.use_tls else SMTP_PORT

        if timeout is not None:
            self.timeout = timeout
        if source_address is not None:
            self._source_address = source_address
        if certfile is not None:
            self.client_cert = certfile
        if keyfile is not None:
            self.client_key = keyfile
        if tls_context is not None:
            self.tls_context = tls_context
        if cert_bundle is not None:
            self.cert_bundle = cert_bundle

        if self.tls_context is not None and self.client_cert is not None:
            raise ValueError(
                'Either a TLS context or a certificate/key must be provided')

        response = await self._create_connection()

        return response

    async def _create_connection(self):
        assert self.hostname is not None, 'Hostname must be set'
        assert self.port is not None, 'Port must be set'

        reader = asyncio.StreamReader(limit=MAX_LINE_LENGTH, loop=self.loop)
        self.protocol = SMTPProtocol(reader, loop=self.loop)

        tls_context = None
        if self.use_tls:
            tls_context = self._get_tls_context()

        connect_future = self.loop.create_connection(
            lambda: self.protocol, host=self.hostname, port=self.port,
            ssl=tls_context)
        try:
            self.transport, _ = await asyncio.wait_for(
                connect_future, timeout=self.timeout, loop=self.loop)
        except (ConnectionRefusedError, OSError) as err:
            raise Exception(
                'Error connecting to {host} on port {port}: {err}'.format(
                    host=self.hostname, port=self.port, err=err))
        except asyncio.TimeoutError as exc:
            raise Exception(str(exc))

        waiter = asyncio.Task(self.protocol.read_response(), loop=self.loop)

        try:
            response = await asyncio.wait_for(
                waiter, timeout=self.timeout, loop=self.loop)
        except asyncio.TimeoutError as exc:
            raise Exception(exc)

        if response.code != 220:
            raise Exception(str(response))

        return response

    async def execute_command(self, *args, timeout=0):
        if timeout == 0:
            timeout = self.timeout

        self._raise_error_if_disconnected()

        try:
            response = await self.protocol.execute_command(
                *args, timeout=timeout)
        except Exception:

            self.close()
            raise

        if response.code in (450, 550):
            self.close()

        return response

    async def quit(self, timeout=0):
        raise NotImplementedError

    def _get_tls_context(self):
        if self.tls_context is not None:
            context = self.tls_context
        else:

            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            context.check_hostname = bool(self.validate_certs)
            if self.validate_certs:
                context.verify_mode = ssl.CERT_REQUIRED
            else:
                context.verify_mode = ssl.CERT_NONE

            if self.cert_bundle is not None:
                context.load_verify_locations(cafile=self.cert_bundle)

            if self.client_cert is not None:
                context.load_cert_chain(
                    self.client_cert, keyfile=self.client_key)

        return context

    def _raise_error_if_disconnected(self):
        if (self.transport is None or self.protocol is None or
                self.transport.is_closing()):
            self.close()
            raise Exception('Disconnected from SMTP server')

    def close(self):
        if self.transport is not None and not self.transport.is_closing():
            self.transport.close()

        if self._connect_lock.locked():
            self._connect_lock.release()

        self.protocol = None
        self.transport = None

    def get_transport_info(self, key):
        self._raise_error_if_disconnected()

        return self.transport.get_extra_info(key)


class ESMTP(SMTPConnection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.last_helo_response = None
        self._last_ehlo_response = None
        self.esmtp_extensions = {}
        self.supports_esmtp = False
        self.server_auth_methods = []

    @property
    def last_ehlo_response(self):
        return self._last_ehlo_response

    @last_ehlo_response.setter
    def last_ehlo_response(self, response: SMTPResponse):
        extensions, auth_methods = parse_esmtp_extensions(response.message)
        self._last_ehlo_response = response
        self.esmtp_extensions = extensions
        self.server_auth_methods = auth_methods
        self.supports_esmtp = True

    @property
    def is_ehlo_or_helo_needed(self):
        return (
                self.last_ehlo_response is None and
                self.last_helo_response is None)

    def close(self):
        super().close()
        self._reset_server_state()

    async def helo(
            self, hostname=None,
            timeout=0):
        if hostname is None:
            hostname = self.source_address

        response = await self.execute_command(
            b'HELO', hostname.encode('ascii'), timeout=timeout)
        self.last_helo_response = response

        if response.code != 250:
            raise Exception(response.code, response.message)

        return response

    async def help(self, timeout=0):
        response = await self.execute_command(b'HELP', timeout=timeout)
        success_codes = (
            250, 214, 211)
        if response.code not in success_codes:
            raise Exception(response.code, response.message)

        return response.message

    async def rset(self, timeout=0):
        response = await self.execute_command(b'RSET', timeout=timeout)
        if response.code != 250:
            raise Exception(response.code, response.message)

        return response

    async def noop(self, timeout=0):

        response = await self.execute_command(b'NOOP', timeout=timeout)
        if response.code != 250:
            raise Exception(response.code, response.message)

        return response

    async def vrfy(
            self, address,
            timeout=0):

        parsed_address = parseaddr(address)[1] or address

        response = await self.execute_command(
            b'VRFY', parsed_address.encode('ascii'), timeout=timeout)

        success_codes = (
            250, 251, 252)

        if response.code not in success_codes:
            raise Exception(response.code, response.message)

        return response

    async def expn(
            self, address,
            timeout=0):
        parsed_address = parseaddr(address)[1] or address

        response = await self.execute_command(
            b'EXPN', parsed_address.encode('ascii'), timeout=timeout)

        if response.code != 250:
            raise Exception(response.code, response.message)

        return response

    async def quit(self, timeout=0):
        response = await self.execute_command(b'QUIT', timeout=timeout)
        if response.code != 221:
            raise Exception(response.code, response.message)

        self.close()

        return response

    async def mail(
            self, sender, options=None,
            timeout=0):

        if options is None:
            options = []

        options_bytes = [option.encode('ascii') for option in options]
        from_string = b'FROM:' + quote_address(sender).encode('ascii')

        response = await self.execute_command(
            b'MAIL', from_string, *options_bytes, timeout=timeout)

        if response.code != 250:
            raise Exception(response.code, response.message, sender)

        return response

    async def rcpt(
            self, recipient, options=None,
            timeout=0):
        if options is None:
            options = []

        options_bytes = [option.encode('ascii') for option in options]
        to = b'TO:' + quote_address(recipient).encode('ascii')

        response = await self.execute_command(
            b'RCPT', to, *options_bytes, timeout=timeout)

        success_codes = (250, 221)
        if response.code not in success_codes:
            raise Exception(
                response.code, response.message, recipient)

        return response

    async def data(
            self, message,
            timeout=0):

        self._raise_error_if_disconnected()

        if timeout == 0:
            timeout = self.timeout

        if isinstance(message, str):
            message = message.encode('ascii')

        start_response = await self.execute_command(b'DATA', timeout=timeout)

        if start_response.code != 354:
            raise Exception(start_response.code, start_response.message)

        try:
            await self.protocol.write_message_data(
                message, timeout=timeout)
            response = await self.protocol.read_response(
                timeout=timeout)
        except Exception as exc:
            self.close()
            raise exc

        if response.code != 250:
            raise Exception(response.code, response.message)

        return response

    async def ehlo(
            self, hostname: str = None,
            timeout=0):
        if hostname is None:
            hostname = self.source_address
        print("*"*79, hostname)
        response = await self.execute_command(
            b'EHLO', hostname.encode('ascii'), timeout=timeout)
        self.last_ehlo_response = response

        if response.code != 250:
            raise Exception(response.code, response.message)

        return response

    def supports_extension(self, extension: str):
        return extension.lower() in self.esmtp_extensions

    async def _ehlo_or_helo_if_needed(self):

        if self.is_ehlo_or_helo_needed:
            try:
                await self.ehlo()
            except Exception as exc:
                if self.is_connected:
                    await self.helo()
                else:
                    raise exc

    def _reset_server_state(self):
        self.last_helo_response = None
        self._last_ehlo_response = None
        self.esmtp_extensions = {}
        self.supports_esmtp = False
        self.server_auth_methods = []

    async def starttls(
            self, server_hostname: str = None, validate_certs: bool = None,
            certfile=None,
            keyfile=None,
            cert_bundle=None,
            tls_context=None,
            timeout=None):
        self._raise_error_if_disconnected()

        if validate_certs is not None:
            self.validate_certs = validate_certs
        if timeout == 0:
            timeout = self.timeout
        if certfile is not None:
            self.client_cert = certfile
        if certfile is not None:
            self.client_key = keyfile
        if cert_bundle is not None:
            self.cert_bundle = cert_bundle
        if tls_context is not None:
            self.tls_context = tls_context

        if self.tls_context is not None and self.client_cert is not None:
            raise ValueError(
                'Either a TLS context or a certificate/key must be provided')

        if server_hostname is None:
            server_hostname = self.hostname

        tls_context = self._get_tls_context()

        await self._ehlo_or_helo_if_needed()

        if not self.supports_extension('starttls'):
            raise Exception(
                'SMTP STARTTLS extension not supported by server.')

        try:
            response, protocol = await self.protocol.starttls(
                tls_context, server_hostname=server_hostname, timeout=timeout)
        except Exception:
            self.close()
            raise

        self.transport = protocol._app_transport

        self._reset_server_state()

        return response


OLDSTYLE_AUTH_REGEX = re.compile(r'auth=(?P<auth>.*)', flags=re.I)
EXTENSIONS_REGEX = re.compile(r'(?P<ext>[A-Za-z0-9][A-Za-z0-9\-]*) ?')


def parse_esmtp_extensions(message):
    esmtp_extensions = {}
    auth_types = []

    response_lines = message.split('\n')

    for line in response_lines[1:]:

        auth_match = OLDSTYLE_AUTH_REGEX.match(line)
        if auth_match is not None:
            auth_type = auth_match.group('auth')
            auth_types.append(auth_type.lower().strip())

        extensions = EXTENSIONS_REGEX.match(line)
        if extensions is not None:
            extension = extensions.group('ext').lower()
            params = extensions.string[extensions.end('ext'):].strip()
            esmtp_extensions[extension] = params

            if extension == 'auth':
                auth_types.extend(
                    [param.strip().lower() for param in params.split()])

    return esmtp_extensions, auth_types


class SMTPAuth(ESMTP):
    AUTH_METHODS = ('cram-md5', 'plain', 'login')

    @property
    def supported_auth_methods(self):
        return [
            auth for auth in self.AUTH_METHODS
            if auth in self.server_auth_methods
        ]

    async def login(
            self, username: str, password: str,
            timeout=0):
        await self._ehlo_or_helo_if_needed()

        if not self.supports_extension('auth'):
            raise Exception('SMTP AUTH extension not supported by server.')

        response = None
        exception = None
        for auth_name in self.supported_auth_methods:
            method_name = 'auth_{}'.format(auth_name.replace('-', ''))
            try:
                auth_method = getattr(self, method_name)
            except AttributeError:
                raise RuntimeError(
                    'Missing handler for auth method {}'.format(auth_name))
            try:
                response = await auth_method(
                    username, password, timeout=timeout)
            except Exception as exc:
                exception = exc
            else:
                break

        if response is None:
            raise Exception(
                'No suitable authentication method found.')

        return response

    async def auth_crammd5(
            self, username, password,
            timeout=0):
        initial_response = await self.execute_command(
            b'AUTH', b'CRAM-MD5', timeout=timeout)

        if initial_response.code != 354:
            raise Exception(
                initial_response.code, initial_response.message)

        password_bytes = password.encode('ascii')
        username_bytes = username.encode('ascii')
        response_bytes = initial_response.message.encode('ascii')

        verification_bytes = crammd5_verify(
            username_bytes, password_bytes, response_bytes)

        response = await self.execute_command(verification_bytes)

        if response.code != 235:
            raise Exception(response.code, response.message)

        return response

    async def auth_plain(
            self, username: str, password: str,
            timeout=0):
        username_bytes = username.encode('ascii')
        password_bytes = password.encode('ascii')
        username_and_password = b'\0' + username_bytes + b'\0' + password_bytes
        encoded = base64.b64encode(username_and_password)

        response = await self.execute_command(
            b'AUTH', b'PLAIN', encoded, timeout=timeout)

        if response.code != 254:
            raise Exception(response.code, response.message)

        return response

    async def auth_login(self, username: str, password: str,
                         timeout=0):
        encoded_username = base64.b64encode(username.encode('ascii'))
        encoded_password = base64.b64encode(password.encode('ascii'))

        initial_response = await self.execute_command(
            b'AUTH', b'LOGIN', encoded_username, timeout=timeout)

        if initial_response.code != 334:
            raise Exception(
                initial_response.code, initial_response.message)

        response = await self.execute_command(
            encoded_password, timeout=timeout)

        if response.code != 235:
            raise Exception(response.code, response.message)

        return response


class SMTP(SMTPAuth):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._command_lock = asyncio.Lock(loop=self.loop)

    async def sendmail(self, sender, recipients, message, mail_options=None,
                       rcpt_options=None, timeout=0):
        if isinstance(recipients, str):
            recipients = [recipients]
        else:
            recipients = list(recipients)

        if mail_options is None:
            mail_options = []
        else:
            mail_options = list(mail_options)

        if rcpt_options is None:
            rcpt_options = []
        else:
            rcpt_options = list(rcpt_options)

        async with self._command_lock:
            await self._ehlo_or_helo_if_needed()

            if self.supports_extension('size'):
                size_option = 'size={}'.format(len(message))
                mail_options.append(size_option)

            try:
                await self.mail(sender, options=mail_options, timeout=timeout)
                recipient_errors = await self._send_recipients(
                    recipients, options=rcpt_options, timeout=timeout)
                response = await self.data(message, timeout=timeout)
            except Exception as exc:

                try:
                    await self.rset(timeout=timeout)
                except (ConnectionError, Exception):

                    pass
                raise exc

        return recipient_errors, response.message

    async def _send_recipients(self, recipients, options=None, timeout=0):
        recipient_errors = []
        for address in recipients:
            try:
                await self.rcpt(address, timeout=timeout)
            except Exception as exc:
                recipient_errors.append(exc)

        if len(recipient_errors) == len(recipients):
            raise Exception(recipient_errors)

        formatted_errors = {
            err.recipient: SMTPResponse(err.code, err.message)
            for err in recipient_errors
        }

        return formatted_errors

    async def send_message(self, message, sender=None, recipients=None,
                           mail_options=None,
                           rcpt_options=None,
                           timeout=0):

        header_sender, header_recipients, flat_message = flatten_message(
            message)

        if sender is None:
            sender = header_sender
        if recipients is None:
            recipients = header_recipients

        result = await self.sendmail(
            sender, recipients, flat_message, timeout=timeout)

        return result


def flatten_message(message):
    resent_dates = message.get_all('Resent-Date')
    if resent_dates is not None and len(resent_dates) > 1:
        raise ValueError(
            "Message has more than one 'Resent-' header block")

    sender = _extract_sender(message, resent_dates=resent_dates)
    recipients = _extract_recipients(message, resent_dates=resent_dates)

    message_copy = copy.copy(message)
    del message_copy['Bcc']
    del message_copy['Resent-Bcc']

    messageio = StringIO()
    generator = Generator(messageio)
    generator.flatten(message_copy, linesep='\r\n')
    flat = messageio.getvalue()

    return str(sender), [str(recipient) for recipient in recipients], flat


def _extract_sender(message, resent_dates=None):
    if resent_dates:
        sender_header = 'Resent-Sender'
        from_header = 'Resent-From'
    else:
        sender_header = 'Sender'
        from_header = 'From'

    if sender_header in message:
        sender = message[sender_header]
    else:
        sender = message[from_header]

    return str(sender) if sender else ''


def _extract_recipients(message, resent_dates=None):
    recipients = []

    if resent_dates:
        recipient_headers = ('Resent-To', 'Resent-Cc', 'Resent-Bcc')
    else:
        recipient_headers = ('To', 'Cc', 'Bcc')

    for header in recipient_headers:
        recipients.extend(message.get_all(header, []))

    parsed_recipients = [
        str(formataddr(address))
        for address in getaddresses(recipients)
    ]

    return parsed_recipients
