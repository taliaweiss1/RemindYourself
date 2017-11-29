#!/usr/bin/env python3
import sys, os
#regex
import re
import hashlib, uuid
from flask import Flask, render_template, session, redirect, url_for, escape, request
from passlib.hash import sha256_crypt
from pymongo import MongoClient
app = Flask(__name__)
client = MongoClient()
db = client.reminders

@app.route('/', methods=['GET', 'POST'])
def index():
    # elif request.form['submit'] == 'Login':
    #     print("index login")
    #     #return redirect(url_for('login'))
    #     return 'clicked login'
    # elif request.form['submit'] == 'BecomeUser':
    #     return redirect(url_for('becomeUser'))
    if "login" in request.form:
        print("login")
        return redirect(url_for('login'))
    elif "becomeUser" in request.form:
        print("become user")
        return redirect(url_for('becomeUser'))
    elif 'username' in session:
        print(session['username'])
        return redirect(url_for('loggedIn'))
    else:
        print("in else")
        return render_template('homepage.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        #check database for user and correct password
        username = request.form['username']
        password = request.form['password']
        if username and password:
            if db.users.find_one({"username": username}).count() == 1:
                print("in if find one")
            #if in database correctly, login as below
                json = db.users.find({"username": username})
                saltedPass = json.password
                if sha256_crypt.verify(password, saltedPass):
                    print("pass verified")
                    session['username'] = request.form['username']
                    return redirect(url_for('loggedIn')
        #return redirect(url_for('index')
    return render_template('login.html')

@app.route('/becomeUser', methods=['GET', 'POST'])
def becomeUser():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username and password:
            if db.users.find({"username": username}).count() == 0:
                print("user doesn't exist")
                saltedPass = sha256_crypt.encrypt(password)
                print("salted pass: " + saltedPass)
                db.users.insert_one({"username": username, "password": saltedPass})
                session['username'] = username
                return redirect(url_for('index'))
    return render_template('becomeUser.html')

@app.route('/loggedIn', methods=['GET', 'POST'])
def loggedIn():
    if "logout" in request.form:
        print("logout clicked")
        return redirect(url_for('logout'))
    return render_template('loggedIn.html')
        

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    print("in logout")
    print(session['username'])
    # remove the username from the session if it's there
    session.pop('username', None)
    #print(session['username'])
    return redirect(url_for('index'))


# set the secret key.  keep this really secret:
app.secret_key = 'A0Zr98j/3yX R~XHH!jmN]LWX/,?RT'


@app.route('/hello')
@app.route('/hello/<name>')
def hello(name=None):
    return render_template('hello.html', name=name)


if __name__ == "__main__":
    print("running")
    app.run(host='0.0.0.0', port=3456)
