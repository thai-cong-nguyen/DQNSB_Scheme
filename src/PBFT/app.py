from flask import Flask

app = Flask(__name__)

if __name__ == '__main__':
    app.debug = True
    app.run(port=8080)