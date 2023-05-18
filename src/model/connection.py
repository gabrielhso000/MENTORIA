import psycopg2


class Conexao():

    def get_connection(self):
        return psycopg2.connect(
            host='127.0.0.1',
            port='5432',
            user='postgres',
            password='123456',
            database='postgres'
        )


conexao = Conexao()
