from __future__ import print_function
import ssl
import sys
from vulntools import Test


class Check(Test):
    NAME = "socket.inet_aton IP parsing issue in ssl.match_hostname"
    SLUG = "ssl-match_hostname-ipv4-trailing"

    def check(self, cert, hostname):
        text = 'ssl.match_hostname(cert, %r)' % hostname
        try:
            ssl.match_hostname(cert, hostname)
            print("%s succeed" % text, file=sys.stderr)
        except ssl.CertificateError:
            print("%s raises CertificateError" % text,
                  file=sys.stderr)
            return

        self.exit_vulnerable()

    def run(self):
        # socket.inet_ntoa(socket.inet_aton('127.1')) == '127.0.0.1'
        cert = {'subject': ((('commonName', 'example.com'),),),
                'subjectAltName': (('DNS', 'example.com'),
                                   ('IP Address', '10.11.12.13'),
                                   ('IP Address', '14.15.16.17'),
                                   ('IP Address', '127.0.0.1'))}
        self.check(cert, '127.1')
        self.check(cert, '14.15.16.17 ')
        self.check(cert, '14.15.16.17 extra data')

        cert = {'subject': ((('commonName', 'example.com'),),),
                'subjectAltName': (
                    ('DNS', 'example.com'),
                    ('IP Address', '2001:0:0:0:0:0:0:CAFE\n'),
                    ('IP Address', '2003:0:0:0:0:0:0:BABA\n'))}
        self.check(cert, '2003::baba ')
        self.check(cert, '2003::baba extra data')

        self.exit_fixed()


if __name__ == "__main__":
    Check().main()
