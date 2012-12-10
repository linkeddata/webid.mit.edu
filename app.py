#!/usr/bin/python
# app.py

from flask import Flask, request, Response, jsonify, make_response, render_template, flash, redirect, url_for, session, escape, g
from flask.ext.sqlalchemy import SQLAlchemy
#from models.database import db_session
#from flask.ext.auth import Auth, AuthUser, login_required, logout
#from models.sa import get_user_class

app = Flask(__name__)
#app.config.from_pyfile('app.cfg')
app.secret_key = 'mysecretkey'

db = SQLAlchemy(app)

#@app.teardown_request
#def shutdown_session(exception=None):
#    db_session.remove()

import pki

def index():
    if request.method == 'POST':
        spkac = request.form.get('spkac','').replace('\n','').replace('\r','')
        issued = pki.sign_spkac(spkac, 'test', 365, altName='http://test/id')
        return Response(issued, mimetype='application/x-x509-user-cert')
    return render_template('index.html')

app.add_url_rule('/', 'index', index, methods=['GET', 'POST'])
