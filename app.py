from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager
from flask_bcrypt import Bcrypt 
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_refresh_token_required,
    get_jwt_identity,
    jwt_required,
    get_raw_jwt
)
from flask_cors import CORS
from os import environ

from db import db
from models.User import User
from models.Tweet import Tweet
from blacklist import BLACKLIST

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = environ.get('SQLALCHEMY_DATABASE_URI')
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["PROPAGATE_EXCEPTIONS"] = True
app.secret_key = environ.get('JWT_SECRET_KEY')

# twitter sample urls
# User profile - e.g. twitter.com/SkipBayless
# Tweet - eg. twitter.com/SkipBayless/status/12423235231
USER_ALREADY_EXISTS = "A user with that username already exists."
CREATED_SUCCESSFULLY = "User created successfully."
INVALID_DATA_FORMAT = "The request payload is not in JSON format."
INVALID_CREDENTIALS="Invalid credentials!"
USER_NOT_FOUND = "User with username as supplied in URL not found."
TWEET_POSTED_SUCCESSFULLY = "Tweet posted successfully."
TWEET_UPDATED_SUCCESSFULLY = "Tweet updated successfully."
TWEET_DELETED_SUCCESSFULLY = "Tweet deleted successfully."
TWEET_NOT_FOUND = "Tweet not found."

@app.before_first_request
def create_tables():
    db.create_all()

jwt = JWTManager(app)


# Signup/Register
@app.route('/signup', methods=['POST'])
def signup():
    if request.is_json:
        data = request.get_json() 
        bcrypt = Bcrypt()
        if User.find_by_username(data["username"]):
            return {"message": USER_ALREADY_EXISTS}, 400
        pw_hash = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        user = User(data["username"], data["email"], pw_hash)
        user.save_to_db()
        return {"message": CREATED_SUCCESSFULLY}, 201
    else:
        return jsonify(
            error = INVALID_DATA_FORMAT
        ), 400

# Login
@app.route('/login', methods=['POST'])
def login():
    if request.get_json():
        data = request.get_json()
        bcrypt = Bcrypt()
        user = User.find_by_username(data["username"])

        if user and bcrypt.check_password_hash(user.password, data["password"]):
            access_token = create_access_token(identity=user.username, fresh=True)
            refresh_token = create_refresh_token(user.id)
            return {"access_token": access_token, "refresh_token": refresh_token, "username": user.username}, 200

        return {"message": INVALID_CREDENTIALS}, 401           
    else:
        return jsonify(
            error = INVALID_DATA_FORMAT
        ), 400

# Logout
@app.route('/logout', methods=['POST'])
@jwt_required
def logout():
    jti = get_raw_jwt()["jti"]
    user_id = get_jwt_identity()
    BLACKLIST.add(jti)
    return {"message": INVALID_CREDENTIALS}, 401

# Refresh token, in case it's necessary for future
@app.route('/refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh_token():
    current_user = get_jwt_identity()
    new_token = create_access_token(identity=current_user, fresh=False)
    return {"access_token": new_token}, 200

@app.route('/')
@app.route('/home')
def home():
    pass

# user profile - user's tweets
@app.route('/<username>', methods=["GET"])
@jwt_required
def user_profile(username):
    user = User.find_by_username(username)
    if user:
        tweets = [tweet.json() for tweet in user.tweets.all()]
        return {"tweets": tweets}
    else:
        return jsonify(
            error = USER_NOT_FOUND
        ), 404

# specific tweet 
@app.route('/<username>/status/<int:id>', methods=["GET"])
@jwt_required
def get_tweet(username, id):
    user = User.find_by_username(username)
    if user:
        tweet = user.tweets.filter_by(id=id).first().json() # handle none case
        return {"tweet": tweet}
    else:
        return jsonify(
            error = USER_NOT_FOUND
        ), 404

# CRUD routes that aren't exposed to public (read is exposed as above)
# CREATE
@app.route('/<username>/tweets', methods=["POST"])
@jwt_required
def tweet(username):
    user = User.find_by_username(username)
    if user:
        data = request.get_json()
        new_tweet = Tweet(data["content"], user.id)
        new_tweet.save_to_db()
        return {"message": TWEET_POSTED_SUCCESSFULLY}, 201
    else:
        return jsonify(
            error = USER_NOT_FOUND
        ), 404

# UPDATE
@app.route('/<username>/tweets/<int:id>', methods=["PUT"])
@jwt_required
def update_tweet(username, id):
    if request.is_json:
        user = User.find_by_username(username)
        if user:
            data = request.get_json()
            tweet = user.tweets.filter_by(id=id).first()
            # PUT should be idempotent
            if tweet:
                tweet.content = data["content"]
            else:
                tweet = Tweet(data["content"], user.id)

            tweet.save_to_db()
            return {"message": TWEET_UPDATED_SUCCESSFULLY}, 200
        else:
            return jsonify(
                error = USER_NOT_FOUND
            ), 404
    else:
        return jsonify(
            error = INVALID_DATA_FORMAT
        ), 400

# DELETE
@app.route('/<username>/tweets/<int:id>', methods=["DELETE"])
@jwt_required
def delete_tweet(username, id):
    user = User.find_by_username(username)
    if user:
        tweet = user.tweets.filter_by(id=id).first()
        if tweet:
            tweet.delete_from_db()
            return {"message": TWEET_DELETED_SUCCESSFULLY}, 200
        else:
            return {"message": TWEET_NOT_FOUND}, 404
    else:
        return jsonify(
            error = USER_NOT_FOUND
        ), 40

if __name__ == "__main__":
    db.init_app(app)
    app.run(port=5000, debug=True)

# {
#     "username": "Stanimalis69",
#     "email": "stanchoi@hotmail.com",
#     "password": "password23"
# }