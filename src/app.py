from flask import Flask, jsonify, request, render_template, make_response
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt

app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://db:27017")
db = client.FlaskApiDB
users = db["Users"]

# -----------------------------------------------------------------


def setResponse(code, msg, data=""):
    if data == "":
        resp = {
            "status": code,
            "message": msg
        }
    else:
        resp = {
            "status": code,
            "message": msg,
            "data": data
        }
    return jsonify(resp)

# -----------------------------------------------------------------


def userExist(username):
    if users.find({"Username": username}).count() == 0:
        return False
    else:
        return True

# -----------------------------------------------------------------


def verifyPass(username, password):
    if not userExist(username):
        return False

    hashedPass = users.find({"Username": username})[0]["Password"]

    if bcrypt.hashpw(password.encode('utf8'), hashedPass) == hashedPass:
        return True
    else:
        return False

# -----------------------------------------------------------------


def countTokens(username):
    tokens = users.find({"Username": username})[0]["Tokens"]
    return tokens

# -----------------------------------------------------------------


class Indexpage(Resource):
    def get(self):
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('index.html'), 200, headers)

# -----------------------------------------------------------------


class SayHello(Resource):
    def get(self):
        return setResponse(200, "hello.... up and running !!")

    def post(self):
        postedData = request.get_json(force=True)
        return setResponse(200, "hello.... up and running !!", postedData)

# -----------------------------------------------------------------


class TokenRefill(Resource):
    def post(self):
        postedData = request.get_json(force=True)
        username = postedData["username"]
        password = postedData["admin_password"]
        monto = postedData["refill"]

        if not userExist(username):
            return setResponse(301, "Invalid Username")

        if not password == "5uperAdmin":
            return setResponse(304, "Invalid password")

        current_tokens = countTokens(username)

        users.update({"Username": username}, { "$set": {"Tokens": current_tokens + monto}})
        return setResponse(200, "Refill added")


# -----------------------------------------------------------------

class TokenCount(Resource):
    def post(self):
        postedData = request.get_json(force=True)
        username = postedData["username"]
        password = postedData["password"]

        if not userExist(username):
            return setResponse(301, "Invalid username")

        correctPass = verifyPass(username, password)
        if not correctPass:
            return setResponse(302, "Invalid Password")

        num_tokens = countTokens(username)

        return setResponse(200, "tokens available", str(num_tokens))


# -----------------------------------------------------------------

class Detect(Resource):
    def post(self):
        postedData = request.get_json(force=True)
        username = postedData["username"]
        password = postedData["password"]
        text1 = postedData["text1"]
        text2 = postedData["text2"]

        if not userExist(username):
            return setResponse(301, "Invalid username")

        correctPass = verifyPass(username, password)
        if not correctPass:
            return setResponse(302, "Invalid Password")

        num_tokens = countTokens(username)

        if num_tokens <= 0:
            return setResponse(303, "Out of tokens")

        import spacy
        nlp = spacy.load('es_core_news_sm') # statistical models for Spanish
        #nlp = spacy.load('en_core_web_sm') # statistical models for English
        
        t1 = nlp(text1)
        t2 = nlp(text2)
        ratio = t1.similarity(t2)

        retJson = {
            "status": 200,
            "ratio": ratio,
            "message": "ratio calculated"
        }

        current_tokens = countTokens(username)
        users.update({"Username": username}, {"$set": {"Tokens": current_tokens-1}})
        return jsonify(retJson)

# -----------------------------------------------------------------


class Register(Resource):
    def post(self):
        postedData = request.get_json(force=True)

        username = postedData["username"]
        password = postedData["password"]  

        if userExist(username):
            return setResponse(301, "Invalid username")

        hashedPass = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        users.insert({
            "Username": username,
            "Password": hashedPass,
            "Tokens": 10
        })
        return setResponse(200, "User added !")


# -----------------------------------------------------------------


api.add_resource(Indexpage, '/')
api.add_resource(Detect, '/detect')
api.add_resource(TokenRefill, '/refill')
api.add_resource(Register, '/register')
api.add_resource(SayHello, '/hello')
api.add_resource(TokenCount, '/tokens')

if __name__ == "__main__":
    app.run(host='0.0.0.0')
