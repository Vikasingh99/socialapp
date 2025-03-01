import psycopg2
from psycopg2 import sql

def get_db_connection():
    host = "localhost"
    user = "postgres"
    password = "password"
    database = "postgres"

    connection = psycopg2.connect(
        host=host,
        user=user,
        password=password,
        dbname=database
    )
    return connection


