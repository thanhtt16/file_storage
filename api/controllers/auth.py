from flask_restful import Resource, reqparse, abort


class AuthLogin(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        pass


class AuthRegister(Resource):
    def post(self):
        pass