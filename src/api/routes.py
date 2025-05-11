"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity


api = Blueprint('api', __name__)

# Allow CORS requests to this API
CORS(api)


bcrypt = Bcrypt()


@api.route('/hello', methods=['POST', 'GET'])
def handle_hello():

    response_body = {
        "message": "Hello! I'm a message that came from the backend, check the network tab on the google inspector and you will see the GET request"
    }

    return jsonify(response_body), 200


@api.route('/public', methods=['POST', 'GET'])
def handle_Public():

    return {
        "message": "Hello! Soy ruta pública"
    }


@api.route('/private', methods=['POST', 'GET'])
@jwt_required()
def handle_Private():

    current_user = get_jwt_identity()
    user = User.query.get(current_user)

    if not user:
        return jsonify({"message": "User not found"}), 404

    return {
        "message": "Hello! Soy ruta privada",
        "user": user.serialize()
    }


@api.route('/user/login', methods=['POST'])
def sing_in():

    data_request = request.get_json()

    if not 'email' in data_request or not 'password' in data_request:
        return jsonify({"message": "Missing email or password"}), 400

    user = User.query.filter_by(email=data_request['email']).first()

    if not user or not bcrypt.check_password_hash(user.password, data_request['password']):
        return jsonify({"message": "Invalid password"}), 401

    try:
        access_token = create_access_token(identity=str(user.id))
        return jsonify({
            "access_token": access_token,
            "user": user.serialize()
        }), 200

    except Exception as e:
        print(e)
        db.session.rollback()
        return jsonify({"message": "Error creating user"}), 400


@api.route('/user/create', methods=['POST'])
def create_user():
    data_request = request.get_json()
    if not 'email' in data_request or not 'password' in data_request:
        return jsonify({"message": "Missing email or password"}), 400
    new_user = User(email=data_request['email'],
                    password=bcrypt.generate_password_hash(data_request['password']).decode('utf-8'))

    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify(new_user.serialize()), 201
    except Exception as e:
        print(e)
        db.session.rollback()
        return jsonify({"message": "Error creating user"}), 400
