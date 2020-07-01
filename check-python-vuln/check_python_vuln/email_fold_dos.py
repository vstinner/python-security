from vulntools import Test


CODE = r"""
import email.policy
policy = email.policy.default.clone(max_line_length=20)
actual = policy.fold('Subject', '\u0105' * 12)
"""


class Check(Test):
    NAME = "Email folding function Denial-of-Service"
    SLUG = "email-fold-dos"

    def run(self):
        try:
            import email.policy   # noqa
        except ImportError:
            # Python 2.7 doesn't have the email.policy module
            self.exit_fixed()

        self.check_subprocess_denial_service(CODE)


if __name__ == "__main__":
    Check().main()
