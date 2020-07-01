from __future__ import print_function
from vulntools import Test
import socket
import sys
import threading


PY3 = (sys.version_info >= (3,))
if PY3:
    import http.client as http_client
    import urllib.request
else:
    import httplib as http_client
    import urllib
    import urllib2


class Server(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.quit = False
        self.listening = threading.Event()
        self.got_connection = False
        self.client_data = None

    def handle_connections(self, sock):
        # check every 50 ms if we have to quit
        poll_timeout = 0.050
        recv_timeout = 1.0

        sock.settimeout(poll_timeout)
        sock.listen(1)
        self.listening.set()

        while not self.quit:
            try:
                client, client_addr = sock.accept()
            except socket.timeout:
                continue

            self.got_connection = True

            client.settimeout(recv_timeout)
            try:
                self.client_data = client.recv(4096)
            except socket.timeout:
                pass

            # immediately close the connection
            client.close()

    def start(self):
        threading.Thread.start(self)
        self.listening.wait(1.0)
        if not self.listening.is_set():
            raise Exception("server failed to start")

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(('127.0.0.1', 0))
            self.host, self.port = sock.getsockname()

            self.handle_connections(sock)
        finally:
            sock.close()

    def stop(self):
        self.quit = True
        self.join()


class Check(Test):
    NAME = "HTTP Header Injection 2 (CVE-2019-9740, CVE-2019-9947)"
    SLUG = "http-header-injection2"

    def check_func(self, func_name, func, url):
        msg = "%s(%r)" % (func_name, url)
        try:
            func(url)
        except http_client.InvalidURL:
            self.log("%s raises InvalidURL: not vulnerable" % msg)
            return
        except Exception as exc:
            err = str(exc)
        else:
            err = None

        if self.server.got_connection:
            self.log("%s sent a network connection: vulnerable!" % msg)
            data = self.server.client_data
            if data is not None:
                self.log("%s sent bytes: %r" % (msg, data))
            self.exit_vulnerable()
        else:
            if err:
                self.log("%s raised %s: vulnerable!" % (msg, err))
                self.exit_error(err)
            else:
                self.log("%s succeeded with no network connection!" % msg)
                self.exit_error("%s succeeded with no network "
                                "connection" % func_name)

    def check_url(self, url):
        if PY3:
            self.check_func('urllib.request.urlopen',
                            urllib.request.urlopen, url)
        else:
            self.check_func('urllib2.urlopen',
                            urllib2.urlopen, url)

            # Note: Python 2 urllib.urlopen() always quotes the URL
            # and so is not vulnerable to HTTP Header Injection

    def run(self):
        self.server = Server()
        try:
            try:
                self.server.start()
            except Exception as exc:
                self.exit_exception(exc)

            self._run()
        finally:
            self.server.stop()

    def _run(self):
        host = self.server.host
        port = self.server.port

        if PY3:
            urllib_quote = urllib.request.quote
        else:
            urllib_quote = urllib.quote

        for scheme in ('http', 'https'):
            # original bug report
            inject = '\r\n\x20hihi\r\n'
            url = '%s://%s:%s%s' % (scheme, host, port, inject)
            self.check_url(url)

            # %HH escape syntax
            quoted_inject = urllib_quote(inject)
            url = '%s://%s:%s%s' % (scheme, host, port, quoted_inject)
            self.check_url(url)

            # Python unit test
            for byte in list(range(0, 0x21)) + [0x7f]:
                char = chr(byte)
                url = ("%s://%s:%s/test%s/"
                       % (scheme, host, port, char))
                self.check_url(url)

        self.exit_fixed()


if __name__ == "__main__":
    Check().main()
