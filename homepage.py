#!/usr/bin/env python3
import sys, os
#regex
import re

from flask import Flask, render_template, session, redirect, url_for, escape, request
app = Flask(__name__)

@app.route('/')
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
        return redirect(url_for('logout'))
    else:
        print("in else")
        return render_template('homepage.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        #check database for user and correct password
        
        #if in database correctly, login as below
        session['username'] = request.form['username']
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/becomeUser', methods=['GET', 'POST'])
def becomeUser():
    return render_template('becomeUser.html')

@app.route('/logout')
def logout():
    # remove the username from the session if it's there
    session.pop('username', None)
    return redirect(url_for('index'))

# set the secret key.  keep this really secret:
app.secret_key = 'A0Zr98j/3yX R~XHH!jmN]LWX/,?RT'

@app.route('/becomeUser')

@app.route('/hello')
@app.route('/hello/<name>')
def hello(name=None):
    return render_template('hello.html', name=name)


if __name__ == "__main__":
    print("running")
    app.run(host='0.0.0.0', port=3456)
