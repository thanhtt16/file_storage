import os
from datetime import datetime
from passlib.hash import pbkdf2_sha256
import rethinkdb as r
from jose import jwt, JWTError
from flask import current_app

from api.utils.errors import ValidationError, DatabaseProcessError

conn = r.connect(db="papers")


class RethinkDBModel(object):
    _table = None

    @classmethod
    def find(cls, id):
        return r.table(cls._table).get(id).run(conn)

    @classmethod
    def filter(cls, predicate):
        return list(r.table(cls._table).filter(predicate).run(conn))

    @classmethod
    def update(cls, id, fields):
        status = r.table(cls._table).get(id).update(fields).run(conn)
        if status['errors']:
            raise DatabaseProcessError("Could not complete the update action")
        return True

    @classmethod
    def delete(cls, id):
        status = r.table(cls._table).get(id).delete().run(conn)
        if status['errors']:
            raise DatabaseProcessError("Could not complete the delete action")
        return True


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


class File(RethinkDBModel):
    _table = 'files'

    @classmethod
    def create(cls, **kwargs):
        name = kwargs.get("name")
        size = kwargs.get("size")
        uri = kwargs.get("uri")
        parent = kwargs.get("parent")
        creator = kwargs.get("creator")

        # Direct parent ID
        parent_id = '0' if parent is None else parent['id']
        doc = {
            'name': name,
            'size': size,
            'uri': uri,
            'parent_id': parent_id,
            'creator': creator,
            'is_folder': False,
            'status': True,
            'date_created': datetime.now(r.make_timezone('+01:00')),
            'date_modified': datetime.now(r.make_timezone('+01:00')),
        }

        res = r.table(cls._table).insert(doc).run(conn)
        doc['id'] = res['generated_keys'][0]

        if parent is not None:
            Folder.add_object(parent, doc['id'])

        return doc
    
    @classmethod
    def move(cls, obj, to):
        previous_folder_id = obj['parent_id']
        previous_folder = Folder.find(previous_folder_id)
        Folder.remove_object(previous_folder, obj['id'])
        Folder.add_object(to, obj['id'])
