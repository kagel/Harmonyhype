import logging
from datetime import datetime, timedelta
from functools import wraps
from decouple import config

import jwt
from flask import Flask, request, jsonify, render_template
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from jwt import ExpiredSignatureError, InvalidTokenError

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data/schedule.db'
app.config['SECRET_KEY'] = config('SECRET_KEY')

db = SQLAlchemy(app)
migrate = Migrate(app, db)


class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    datetime = db.Column(db.DateTime, nullable=False)


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except ExpiredSignatureError:
            app.logger.error('Token has expired!')
            return jsonify({'message': 'Token has expired!'}), 401
        except InvalidTokenError as e:
            app.logger.error(f'Token is invalid! Error: {e}, token: {token}')
            return jsonify({'message': 'Token is invalid!'}), 401
        except Exception as e:
            app.logger.error(f'Unexpected error occurred during token validation: {e}')
            return jsonify({'message': 'Token validation failed!'}), 500
        return f(*args, **kwargs)

    return decorator


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/update')
@token_required
def update_page():
    return render_template('update.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if username == 'admin' and password == config('ADMIN_PASSWORD'):
            token = jwt.encode({
                'user': username,
                'exp': datetime.utcnow() + timedelta(minutes=30)
            }, app.config['SECRET_KEY'])
            return jsonify({'token': token})
        return jsonify({'message': 'Invalid Credentials!'}), 401


@app.route('/schedule', methods=['GET'])
def get_schedule():
    event = Event.query.first()
    if event:
        return jsonify({'datetime': event.datetime.strftime('%Y-%m-%d %H:%M:%S')})
    return jsonify({'message': 'Event not found'}), 404


@app.route('/schedule', methods=['POST'])
@token_required
def update_schedule():
    data = request.get_json()
    new_datetime_str = data.get('datetime')
    if not new_datetime_str:
        return jsonify({'message': 'Datetime is required!'}), 400

    new_datetime = datetime.strptime(new_datetime_str, '%Y-%m-%d %H:%M:%S')

    event = Event.query.first()

    if not event:
        new_event = Event(datetime=new_datetime)
        db.session.add(new_event)
        db.session.commit()
        return jsonify({'message': 'Event created successfully'}), 201

    event.datetime = new_datetime
    db.session.commit()
    return jsonify({'message': 'Event updated successfully'}), 200


if __name__ == "__main__":
    log_formatter = logging.Formatter(
        "[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s")

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.DEBUG)
    stream_handler.setFormatter(log_formatter)

    app.logger.addHandler(stream_handler)
    app.logger.setLevel(logging.DEBUG)

    app.logger.info("Starting Flask application...")

    app.run(debug=True, port=5004)
