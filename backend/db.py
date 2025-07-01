
import mysql.connector

def get_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="Vishnu2304@@@",  
        database="local_services"
    )
