from flask import Flask, request, json, jsonify
from flask_restx import Api, Resource
from werkzeug.exceptions import HTTPException, BadRequest
from src.server.instance import server
from src.model.connection import *
from psycopg2.extras import DictCursor
import bcrypt
import re

app, api = server.app, server.api


# MOCK - PARA RETORNAR DADOS FIXOS, CASO NECESSARIO
# usuarios_db = [
#    {'id': 1, 'nome': 'USUARIO 1'},
#    {'id': 2, 'nome': 'USUARIO 2'}
# ]


# Função para verificar se um usuário já existe no banco de dados

class VerificarUsuario(Resource):

    def post(self, ):

        content_type = request.headers.get('Content-Type')
        if content_type == 'application/json':

            jsonUsuario = request.json

        else:
            return 'Content-Type not supported!'

            # sql = "SELECT * FROM tbl_usuarios WHERE email = %s OR usuario = %s"
            # val = (email, usuario)
            # conn = conexao.get_connection()
            # cur = conn.cursor(cursor_factory=DictCursor)
            # cur.execute(sql, val)
            # resultado = cur.fetchone()

            # if resultado:
            #    return True
            # else:
            #    return False


@api.route('/usuario')
class Usuario(Resource):

    def validate_fields(self, email, usuario, senha):
        if not email:
            return json.dumps({"error": "Campo Email é obrigatório"})
        elif not usuario:
            return json.dumps({"error": "Campo Usuario é obrigatório"})
        elif not senha:
            return json.dumps({"error": "Campo Senha é obrigatório"})
        else:
            return json.dumps({"success": "All fields are valid"})

    def validate_password_rules(self, password):

        # Define the password rules
        rules = {
            'minimum_length': 8,
            'uppercase_required': True,
            'lowercase_required': True,
            'numeric_required': True,
            'special_character_required': True,
        }

        # Validate the password against the rules
        failed_rules = []
        if len(password) < rules['minimum_length']:
            failed_rules.append('Password length must be at least {} characters'.format(rules['minimum_length']))
        if rules['uppercase_required'] and not re.search(r'[A-Z]', password):
            failed_rules.append('Password must contain at least one uppercase letter')
        if rules['lowercase_required'] and not re.search(r'[a-z]', password):
            failed_rules.append('Password must contain at least one lowercase letter')
        if rules['numeric_required'] and not re.search(r'\d', password):
            failed_rules.append('Password must contain at least one numeric digit')
        if rules['special_character_required'] and not re.search(r'[!@#$%^&*()-=_+]', password):
            failed_rules.append('Password must contain at least one special character (!@#$%^&*()-=_+)')

        # Return the result
        if failed_rules:
            return json.dumps({"error": "Password validation failed", "failed_rules": failed_rules})
        else:
            return json.dumps({"success": "Password passed all validation rules"})


    def get(self, ):
        with conexao.get_connection() as conn:
            cur = conn.cursor(cursor_factory=DictCursor)
            cur.execute("SELECT * FROM tbl_usuarios")
            rows = cur.fetchall()
            cur.close()
            data = [row_to_dict(x) for x in rows]
            return data

    def post(self, ):

        # Verifica se conteudo do post esta no formato JSON. Do contrario devolve erro
        content_type = request.headers.get('Content-Type')
        if content_type == 'application/json':
            # Pega json
            jsonUsuario = request.json

            # Validar parametros de entrada
            json_response = self.validate_fields(jsonUsuario['email'], jsonUsuario['usuario'], jsonUsuario['senha'])
            data = json.loads(json_response)
            if 'error' in data:
                return data['error']

            # Validar regras de senha
            json_response = self.validate_password_rules(jsonUsuario['senha'])
            data = json.loads(json_response)
            if 'error' in data:
                return data['error']

            # Validar se usuario/senha ja existem no banco





            # Usuario validado - Insere no Banco de dados

            with conexao.get_connection() as conn:
                cur = conn.cursor()
                sql = "INSERT INTO tbl_usuarios (id, email, usuario, senha) VALUES (%s, %s, %s, %s) "
                hashed = bcrypt.hashpw(jsonUsuario['senha'].encode('utf-8'), bcrypt.gensalt())
                stored_password = hashed.decode("utf-8")
                data = (jsonUsuario['id'], jsonUsuario['email'], jsonUsuario['usuario'], stored_password,)
                cur.execute(sql, data)

                conn.commit()
                cur.close()

            return 'Usuario criado com sucesso!'
        else:
            return 'Content-Type not supported!'


@api.route('/usuario/<int:id>')
class BuscarUsuarioPorId(Resource):
    def get(self, id):
        with conexao.get_connection() as conn:
            cur = conn.cursor(cursor_factory=DictCursor)
            cur.execute("SELECT * FROM tbl_usuarios where id = %s", str(id))
            rows = cur.fetchall()
            cur.close()
            data = [row_to_dict(x) for x in rows]
            return data


@api.route('/usuario/<string:nomeUsuario>')
class BuscarUsuarioPorNome(Resource):
    def get(self, nomeUsuario):
        with conexao.get_connection() as conn:
            cur = conn.cursor(cursor_factory=DictCursor)
            sql = "SELECT * FROM tbl_usuarios where usuario = %s"
            data = (nomeUsuario,)
            cur.execute(sql, data)
            rows = cur.fetchall()
            cur.close()
            data = [row_to_dict(x) for x in rows]
            return data


@api.route('/validarUsuario')
class ValidarUsuario(Resource):
    def post(self, ):

        content_type = request.headers.get('Content-Type')
        if content_type == 'application/json':

            jsonUsuario = request.json
            with conexao.get_connection() as conn:
                cur = conn.cursor(cursor_factory=DictCursor)
                sql = "SELECT senha FROM tbl_usuarios where usuario = %s "
                data = (jsonUsuario['usuario'],)
                cur.execute(sql, data)
                row = cur.fetchone()

                if row == None:
                    cur.close()
                    return dict({"mensagem": "usuario nao localizado"})

                else:
                    senhaDB = row['senha']
                    cur.close()

                    passwordInput = jsonUsuario['senha'].encode("utf-8")
                    if bcrypt.checkpw(passwordInput, senhaDB.encode("utf-8")):
                        return dict({"mensagem": "Usuario validado"})
                    else:
                        return dict({"mensagem": "Usuario/Senha invalidos"})
        else:
            return 'Content-Type not supported!'


def row_to_dict(row):
    return dict({
        'id': row['id'],
        'email': row['email'],
        'usuario': row['usuario'],
        'senha': row['senha']
    })


# Manipuladores (Handlers) de exceção

@app.errorhandler(BadRequest)
def handle_bad_request(e):
    return 'bad request!', 400


@api.errorhandler(HTTPException)
def handle_exception(e):
    """Return JSON instead of HTML for HTTP errors."""
    # start with the correct headers and status code from the error
    response = e.get_response()
    # replace the body with JSON
    response.data = json.dumps({
        "code": e.code,
        "name": e.name,
        "description": e.description,
    })
    response.content_type = "application/json"
    return response.data
