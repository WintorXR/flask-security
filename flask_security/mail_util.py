"""
    Mail Util class for working with flask_mailman, which is a more modern mail implementation.

    Originally from the following module:
    flask_security.mail_util
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Utility class providing methods for validating, normalizing and sending emails.

    :copyright: (c) 2020-2021 by J. Christopher Wagner (jwag).
    :license: MIT, see LICENSE for more details.

    While this default implementation uses FlaskMail - we want to make sure that
    FlaskMail isn't REQUIRED (if this implementation isn't used).
"""
from typing import Any, TYPE_CHECKING

from email_validator import validate_email
from flask import current_app  # noqa
from flask_mailman import EmailMessage

if TYPE_CHECKING:  # pragma: no cover
    from flask import Flask
    from .datastore import User


class MailUtil:
    """
    Utility class providing methods for validating, normalizing and sending emails.

    This default class uses the email_validator package to handle validation and
    normalization, and the flask_mail package to send emails.

    To provide your own implementation, pass in the class as ``mail_util_cls``
    at init time.  Your class will be instantiated once as part of app initialization.

    """

    validator_args = {}

    def __init__(self, app: "Flask"):
        """Instantiate class.

        param app: The Flask application being initialized
        """
        self.app = app

    def send_mail(self, template: str, subject: str, recipient: str, sender: str | tuple,  # noqa
                  body: str, html: str, user: "User", **kwargs: Any) -> None:  # noqa
        """Send an email via the Flask-Mail extension.

        param template: the Template name. The message has already been rendered
            however this might be useful to differentiate why the email is being sent
        :param subject: Email subject
        :param recipient: Email recipient
        :param sender: who to send email as (see :py:data:`SECURITY_EMAIL_SENDER`)
        :param body: the rendered body (text)
        :param html: the rendered body (html)
        :param user: the user model
        """
        # if html:
        #     headers = {'Content-Type': 'text/html; charset=UTF-8'}
        #     msg = EmailMessage(subject, body=html, from_email=sender, to=[recipient], headers=headers)
        if body:  # pragma: no cover
            msg = EmailMessage(subject, body=body, from_email=sender, to=[recipient])
        else:  # pragma: no cover
            self.app.logger.warning(f'mail on {subject} missing body')
            return
        self.app.logger.warning(f'send mail on {subject} to {recipient}')  # pragma: no cover
        msg.send()  # pragma: no cover

    def normalize(self, email: str) -> str:
        """
        Given an input email - return a normalized version.
        Must be called in app context and uses :py:data:`SECURITY_EMAIL_VALIDATOR_ARGS`
        config variable to pass any relevant arguments to
        email_validator.validate_email() method.

        Will throw email_validator.EmailNotValidError if email isn't even valid.
        """
        return validate_email(email, **self.validator_args).email  # pragma: no cover

    def validate(self, email: str) -> str:
        """
        Validate the given email.
        If valid, the normalized version is returned.

        ValueError is thrown if not valid.
        """
        return validate_email(email, **self.validator_args).email  # pragma: no cover
