# main.py
#from flask import Flask
#from blueprints.route import bp_usuarios
#app = Flask(__name__)
#app.register_blueprint(bp_usuarios)
#if __name__ == '__main__':
#    app.run()



#versao atualizada

from src.server.instance import server
from src.controllers.usuario import *

server.run()



