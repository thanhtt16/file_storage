import os
from datetime import datetime
from passlib.hash import pbkdf2_sha256
import rethinkdb as r
from jose import jwt, JWTError
from flask import current_app

from api.utils.errors import ValidationError

conn = r.connect(db="papers")


class RethinkDBModel(object):
    pass


class User(RethinkDBModel):
    _table = 'users'

    @classmethod
    def create(cls, **kwargs):
        fullname = kwargs.get("fullname")
        email = kwargs.get("email")
        password = kwargs.get("password")
        password_conf = kwargs.get("password_conf")
        if password != password_conf:
            raise ValidationError(
                "Password and Confirm password need to be the same values")
        password = cls.hash_password(password)
        doc = {
            "fullname": fullname,
            "email": email,
            "password": password,
            "date_created": datetime.now(r.make_timezone('+01:00')),
            "date_modified": datetime.now(r.make_timezone('+01:00'))
        }
        r.table(cls._table).insert(doc).run(conn)

    @classmethod
    def validate(cls, email, password):
        docs = list(r.table(cls._table).filter({"email": email}).run(conn))
        if not len(docs):
            raise ValidationError(
                "Could not find the email address you specified")
        _hash = docs[0]["password"]
        if cls.verify_password(password, _hash):
            try:
                token = jwt.encode(
                    {
                        'id': docs[0]['id']
                    },
                    current_app.config['SECRET_KEY'],
                    algorithm='HS256')
                return token
            except JWTError:
                raise ValidationError(
                    "There was a problem while trying to create a JWT token.")
        else:
            raise ValidationError("The password you inputted was incorrect")

    @staticmethod
    def hash_password(password):
        return pbkdf2_sha256.encrypt(password, round=200000, salt_size=16)

    @staticmethod
    def verify_password(password, _hash):
        return pbkdf2_sha256.verify(password, _hash)