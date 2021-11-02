from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask import jsonify, request, make_response
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'thisismysecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:9666@localhost:5432/postgres2'
db = SQLAlchemy(app)


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    token = db.Column(db.Text, nullable=False, default='')


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token')

        if not token:
            return '<h1>Hello, token is missing </h1>', 403

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
        except:
            return '<h1>Hello, Could not verify the token</h1>', 403

        return f(*args, **kwargs)

    return decorated


@app.route("/protected")
@token_required
def protected():
    return '<h1>Hello, token which is provided is correct</h1>'


@app.route("/")
@app.route("/login")
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = Users.query.filter_by(username=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if auth and auth.password == user.password:
        token = jwt.encode({'username': user.username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
                           app.config['SECRET_KEY'])
        user = Users.query.filter_by(username=auth.username).first()
        user.token = token
        db.session.commit()
        return jsonify({'token': token.decode('UTF-8')})

    return make_response('Could not verify!', 401, {'WWW-Authenticate': 'Basic realm="Login required'})


if __name__ == '__main__':
    app.run(debug=True)