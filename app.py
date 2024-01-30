from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, create_access_token, unset_jwt_cookies
from flask_cors import CORS
from sqlalchemy.orm import relationship
from flask_bcrypt import Bcrypt
from datetime import timedelta, datetime
import pytz

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://admin:admin@localhost:3306/expenses'
app.config['JWT_SECRET_KEY'] = 'Hl0$1:)8i[55$9H)3(2bh5byli2i[5i"7,S'
app.config['SECRET_KEY'] = 'Hl0$1:)8i[55$9H)3(2bh5byli2i[5i"7,S'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=30)
jwt = JWTManager(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
CORS(app, supports_credentials=True, methods=['GET', 'POST', 'PUT', 'DELETE'])

mxtz = pytz.timezone('America/Mexico_City')

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    movements = relationship('Movements', back_populates='user')

class Movements(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(255))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(mxtz))
    user = relationship('User', back_populates='movements')
    categories = relationship('Categories', back_populates='movements')

class Categories(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    type_id = db.Column(db.Integer, db.ForeignKey('type.id'), nullable=False)
    type = relationship('Type', back_populates='categories')
    movements = relationship('Movements', back_populates='categories')

class Type(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    categories = relationship('Categories', back_populates='type')
    
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    user = User.query.filter_by(email=email).first()
    
    if user and bcrypt.check_password_hash(user.password, password):
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token, user_data={'id': user.id, 'name': user.name, 'email': user.email}), 200
    else:
        return jsonify({'error': 'Credenciales incorrectas'}), 401

@app.route('/logout', methods=['GET'])
@jwt_required()
def logout():
    current_user = get_jwt_identity()
    response = jsonify({'message': 'Logout exitoso'})
    unset_jwt_cookies(response)
    return response, 200

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({'error': 'El usuario ya existe'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(name=name, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    access_token = create_access_token(identity=new_user.id)
    return jsonify(access_token=access_token, user_data={'id': new_user.id, 'name': name, 'email': email}), 201

@app.route('/categories', methods=['GET'])
@jwt_required()
def get_categories_with_totals():
    current_user_id = get_jwt_identity()
    with app.app_context():
        categories_with_totals = db.session.query(
            Categories.id.label('category_id'),
            Categories.name.label('category_name'),
            Type.name.label('type_name'),
            func.sum(Movements.amount).label('total_amount')
        ) \
            .join(Type) \
            .outerjoin(Movements, (Categories.id == Movements.category_id) & (Movements.user_id == current_user_id)) \
            .group_by(Categories.id, Type.id) \
            .all()

        categories_data = [
            {
                'id': category.category_id,
                'name': category.category_name,
                'type': category.type_name,
                'total_amount': category.total_amount or 0
            }
            for category in categories_with_totals
        ]

        return jsonify(categories_data)
    
@app.route('/movements_total', methods=['GET'])
@jwt_required()
def get_total_movements():
    current_user_id = get_jwt_identity()
    with app.app_context():
        total_income = db.session.query(func.sum(Movements.amount).label('total_income')) \
        .join(Categories, Movements.category_id == Categories.id) \
        .filter(Movements.user_id == current_user_id, Categories.type_id == 1) \
        .first()

        total_expense = db.session.query(func.sum(Movements.amount).label('total_expense')) \
            .join(Categories, Movements.category_id == Categories.id) \
            .filter(Movements.user_id == current_user_id, Categories.type_id == 0) \
            .first()

        total_movements = {'total_income': total_income.total_income or 0, 'total_expense': total_expense.total_expense or 0}

        return jsonify(total_movements)

@app.route('/movements', methods=['GET'])
@jwt_required()
def get_movements():
    current_user = get_jwt_identity()
    with app.app_context():
        movements = db.session.query(Movements, Categories.name.label('category_name')) \
            .join(Categories, Movements.category_id == Categories.id) \
            .filter(Movements.user_id == current_user) \
            .add_columns(Movements.id, Movements.amount, Movements.description, Movements.created_at, Categories.name.label('category_name')) \
            .all()

        movements_data = [{
            'id': movement.id,
            'amount': movement.amount,
            'description': movement.description,
            'created_at': movement.created_at,
            'category_name': movement.category_name
        } for movement, category_name in movements]
        
        return jsonify(movements_data)

@app.route('/movements', methods=['POST'])
@jwt_required()
def add_movement():
    current_user = get_jwt_identity()
    with app.app_context():
        new_movement = request.get_json()
        print(new_movement)
        name = new_movement.get('name')
        category = new_movement.get('category')
        amount = new_movement.get('amount')
        user_id = current_user

        movement = Movements(description=name, category_id=category, amount=amount, user_id=user_id)
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