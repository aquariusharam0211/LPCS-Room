from flask import Flask, request, jsonify
from flask_mysql import MySQL

app = Flask(__name__)
app.config['MYSQL_DATABASE_HOST'] = 'localhost'
app.config['MYSQL_DATABASE_USER'] = 'root'
app.config['MYSQL_DATABASE_PASSWORD'] = '비밀번호'
app.config['MYSQL_DATABASE_DB'] = 'your_db'

mysql = MySQL(app)

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    user_id = data.get('id')
    pw = data.get('pw')
    conn = mysql.connect()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (id, pw) VALUES (%s, %s)", (user_id, pw))
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({'message': '저장 완료'})

if __name__ == '__main__':
    app.run(debug=True)

@app.route('/users', methods=['GET'])
def get_users():
    conn = mysql.connect()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users")
    users = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(users)