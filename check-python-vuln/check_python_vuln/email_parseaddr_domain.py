import email.errors
import email.utils
from vulntools import Test
import sys

PY2 = (sys.version_info < (3,))
if not PY2:
    import email._header_value_parser


class Check(Test):
    NAME = "email.utils.parseaddr mistakenly parse an email"
    SLUG = "email-parseaddr-domain"

    def check_addr_spec(self):
        HeaderParseError = email.errors.HeaderParseError
        for addr in (
            'star@a.star@example.com',
            'star@a@example.com',
            'star@172.17.0.1@example.com',
        ):
            try:
                email._header_value_parser.get_addr_spec(addr)
            except HeaderParseError:
                pass
            else:
                self.log("email._header_value_parser.get_addr_spec(%r) "
                         "did not raise HeaderParseError exception: "
                         "vulnerable!"
                         % (addr,))
                self.exit_vulnerable()

    def run(self):
        for addr in (
            'a@b@c',
            'a@b.c@c',
            'a@172.17.0.1@c',
        ):
            result = email.utils.parseaddr(addr)
            if result != ('', ''):
                self.log("email.utils.parseaddr(%r) returns %r: vulnerable!"
                         % (addr, result))
                self.exit_vulnerable()

        if not PY2:
            self.check_addr_spec()

        self.exit_fixed()


if __name__ == "__main__":
    Check().main()
