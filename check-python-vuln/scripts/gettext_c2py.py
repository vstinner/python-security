import gettext
from vulntools import Test


class Check(Test):
    NAME = "gettext.c2py (bpo-28563)"
    SLUG = "gettext-c2py"

    def callback(self):
        self.exit_vulnerable()

    def run(self):
        try:
            py = gettext.c2py("n()")
        except ValueError:
            self.exit_fixed()
        else:
            py(self.callback)

        self.exit_error()


if __name__ == "__main__":
    Check().main()
