import os
from dotenv import load_dotenv
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import jwt
import datetime
from urllib.parse import quote_plus

# Carregar variáveis do arquivo .env
load_dotenv()

app = Flask(__name__)

# Configuração do Flask utilizando variáveis de ambiente
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# Ajuste para carregar a URI correta do banco de dados
db_uri = os.getenv('DATABASE_URL')
if db_uri is None:
    raise ValueError("A variável de ambiente 'DATABASE_URL' não está definida.")

# Codificação apenas da senha na URI do banco de dados
if '://' in db_uri:
    parts = db_uri.split('://')
    scheme = parts[0]
    rest = parts[1]
    
    # Se a senha estiver presente, codifique-a
    user_info, host_info = rest.split('@')
    username, password = user_info.split(':')
    password_encoded = quote_plus(password)
    db_uri_encoded = f"{scheme}://{username}:{password_encoded}@{host_info}"

    app.config['SQLALCHEMY_DATABASE_URI'] = db_uri_encoded
else:
    raise ValueError("Formato da URL do banco de dados é inválido.")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
CORS(app)

# Classe de usuários
class Users(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# Rota para registro de usuário
@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    if not name or not email or not password:
        return jsonify({'message': 'Por favor, preencha todos os campos'}), 400

    existing_user = Users.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({'message': 'Usuário já registrado com este email'}), 400

    hashed_password = generate_password_hash(password, method='sha256')
    new_user = Users(name=name, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'Usuário registrado com sucesso'}), 201

# Rota para login de usuário
@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Por favor, preencha todos os campos'}), 400

    user = Users.query.filter_by(email=email).first()

    if not user:
        return jsonify({'message': 'Credenciais inválidas: usuário não encontrado'}), 401

    if not check_password_hash(user.password, password):
        return jsonify({'message': 'Credenciais inválidas: senha incorreta'}), 401

    # Geração do token JWT
    token = jwt.encode(
        {'user_id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)},
        app.config['SECRET_KEY'],
        algorithm='HS256'
    )

    return jsonify({'token': token, 'redirect_url': '/dashboard'}), 200

# Rota para redefinição de senha
@app.route('/auth/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    email = data.get('email')
    new_password = data.get('newPassword')

    if not email or not new_password:
        return jsonify({'message': 'Por favor, preencha todos os campos'}), 400

    user = Users.query.filter_by(email=email).first()

    if not user:
        return jsonify({'message': 'Usuário não encontrado'}), 404

    hashed_password = generate_password_hash(new_password, method='sha256')
    user.password = hashed_password
    db.session.commit()

    return jsonify({'message': 'Senha redefinida com sucesso'}), 200

# Inicialização do aplicativo
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)
