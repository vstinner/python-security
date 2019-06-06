from vulntools import Test
import socket
import sys
import threading


PY3 = (sys.version_info >= (3,))
if PY3:
    import http.client
    import urllib.request
else:
    import httplib
    import urllib
    import urllib2


class Server(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.quit = False
        self.listening = threading.Event()
        self.got_connection = False

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
        sys.stderr.write("Test %s() with URL: %r\n" % (func_name, url))
        sys.stderr.flush()

        try:
            if PY3:
                invalid_url_exc = http.client.InvalidURL
            else:
                invalid_url_exc = httplib.InvalidURL
        except AttributeError as exc:
            self.exit_vulnerable("missing InvalidURL exception: %s" % exc)

        try:
            func(url)
        except invalid_url_exc:
            # not vulnerable
            return
        except IOError as exc:
            if self.server.got_connection:
                # handle the error below
                pass
            else:
                self.exit_error(str(exc))

        if self.server.got_connection:
            self.exit_vulnerable("%s sent a network connection"
                                 % func_name)

    def check_url(self, url):
        if PY3:
            self.check_func('urllib.request.urlopen', urllib.request.urlopen, url)
        else:
            #self.check_func('urllib.urlopen', urllib.urlopen, url)
            self.check_func('urllib2.urlopen', urllib2.urlopen, url)

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

        for scheme in ('http', 'https'):
            # origin bug report
            inject = '\r\n\x20hihi\r\n'
            url = '%s://%s:%s%s' % (scheme, host, port, inject)
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
