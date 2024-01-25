from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, create_access_token
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://admin:admin@localhost:3306/expenses'
app.config['JWT_SECRET_KEY'] = 'Hl0$1:)8i[55$9H)3(2bh5byli2i[5i"7,S'
app.config['SECRET_KEY'] = 'Hl0$1:)8i[55$9H)3(2bh5byli2i[5i"7,S'
jwt = JWTManager(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
CORS(app, supports_credentials=True, methods=['GET', 'POST', 'PUT', 'DELETE'])

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(60))
    
    def is_active(self):
        return True

class Movements(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(10))
    category = db.Column(db.String(50))
    amount = db.Column(db.Float)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref = db.backref('movements', lazy='dynamic'))
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
    
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(name=username).first()
    
    if user and bcrypt.check_password_hash(user.password, password):
        login_user(user)
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({'message': 'Credenciales incorrectas'}), 401

@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logout exitoso'}), 200

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    existing_user = User.query.filter_by(name=username).first()
    if existing_user:
        return jsonify({'message': 'El usuario ya existe'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(name=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    access_token = create_access_token(identity=new_user.id)
    return jsonify(access_token=access_token), 201

@app.route('/movements', methods=['GET'])
@jwt_required()
def get_movements():
    current_user = get_jwt_identity()
    with app.app_context():
        movements = Movements.query.all()
        list_movements = []
        for movement in movements:
            list_movements.append({
                'id': movement.id,
                'type': movement.type,
                'category': movement.category,
                'amount': movement.amount,
                'user_id': movement.user_id
            })
        return jsonify({'movements': list_movements})

@app.route('/movements', methods=['POST'])
@jwt_required()
def add_movement():
    current_user = get_jwt_identity()
    with app.app_context():
        new_movement = request.get_json()
        type = new_movement.get('type')
        category = new_movement.get('category')
        amount = new_movement.get('amount')
        user_id = new_movement.get('user_id')

        movement = Movements(type=type, category=category, amount=amount, user_id=user_id)
        db.session.add(movement)
        db.session.commit()

        return jsonify({'mensaje': 'Movimiento agregado exitosamente'})

@app.route('/movements/<int:movement_id>', methods=['DELETE'])
@jwt_required()
def delete_movement(movement_id):
    current_user = get_jwt_identity()
    with app.app_context():
        movement = Movements.query.get(movement_id)

        if movement:
            db.session.delete(movement)
            db.session.commit()
            return jsonify({'mensaje': 'Movimiento eliminado exitosamente'})
        else:
            return jsonify({'mensaje': 'Movimiento no encontrado'}), 404

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)