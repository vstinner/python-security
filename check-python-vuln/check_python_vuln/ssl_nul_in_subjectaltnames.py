from vulntools import Test


class Check(Test):
    NAME = "SLL NUL in subjectAltNames (CVE-2013-4238)"
    SLUG = "ssl-null-subjectaltnames"

    def run(self):
        try:
            import _ssl
        except ImportError as exc:
            self.exit_error("missing _ssl module: %s" % exc)

        filename = self.data_file("nullbytecert.pem")
        _ssl._test_decode_cert(filename)
        self.exit_fixed()


if __name__ == "__main__":
    Check().main()
