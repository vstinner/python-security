from vulntools import Test


class Check(Test):
    NAME = "SSL CRL DPS DoS (CVE-2019-5010)"
    SLUG = "ssl-crl-dps-dos"

    def run(self):
        try:
            import _ssl
        except ImportError as exc:
            self.exit_error("missing _ssl module: %s" % exc)

        filename = self.data_file("CVE-2019-5010.pem")
        _ssl._test_decode_cert(filename)
        self.exit_fixed()


if __name__ == "__main__":
    Check().main()
