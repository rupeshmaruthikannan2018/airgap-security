from flask import Flask, request
import sqlite3
import subprocess

app = Flask(__name__)

@app.route("/user")
def user():
    user_id = request.args.get("id")

    conn = sqlite3.connect("users.db")
    query = "SELECT * FROM users WHERE id=" + user_id

    result = conn.execute(query).fetchall()

    return str(result)


@app.route("/ping")
def ping():
    host = request.args.get("host")

    result = subprocess.check_output(
        "ping " + host,
        shell=True
    )

    return result


if __name__ == "__main__":
    app.run()