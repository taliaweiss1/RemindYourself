#!/usr/bin/env python3
import sys, os
#regex
import re
import hashlib, uuid
from flask import Flask, render_template, session, redirect, url_for, escape, request
from passlib.hash import sha256_crypt
from pymongo import MongoClient
from datetime import datetime
app = Flask(__name__)
client = MongoClient()
db = client.reminders

@app.route('/', methods=['GET', 'POST'])
def index():
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
    if request.method == 'POST' and "login" in request.form:
        #check database for user and correct password
        username = request.form['username']
        password = request.form['password']
        if username and password:
            if db.users.find_one({"username": username}):
                print("in if find one")
                cursor = db.users.find_one({"username": username})
                saltedPass = cursor['password']
                if sha256_crypt.verify(password, saltedPass):
                    print("pass verified")
                    session['username'] = request.form['username']
                    return redirect(url_for('loggedIn'))
                print("doesn't match")
    if "back" in request.form:
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/becomeUser', methods=['GET', 'POST'])
def becomeUser():
    if request.method == 'POST' and "becomeUser" in request.form:
        username = request.form['username']
        password = request.form['password']
        phoneNumber = request.form['phoneNumber']
        if username and password and phoneNumber:
            if db.users.find({"username": username}).count() == 0:
                regex = re.compile('\d{10}')
                match = regex.match(phoneNumber)
                if match is not None:
                    saltedPass = sha256_crypt.encrypt(password)
                    db.users.insert_one({"username": username, "password": saltedPass, "phoneNumber": phoneNumber})
                    session['username'] = username
                    session['phoneNumber'] = phoneNumber
                    return redirect(url_for('index'))
    if "back" in request.form:
        return redirect(url_for('index'))
    return render_template('becomeUser.html')

@app.route('/loggedIn', methods=['GET', 'POST'])
def loggedIn():
    username = session['username']
    if "logout" in request.form:
        print("logout clicked")
        return redirect(url_for('logout'))
    if "createReminder" in request.form:
        print("here")
        reminderName = request.form['reminderName']
        reminderDay = request.form['reminderDay']
        reminderTime = request.form['reminderTime']
        reminderText = request.form['reminderText']
        if reminderName and reminderTime and reminderDay and reminderText:
            print("reminder name: " + reminderName)
            print("reminder time: " + reminderTime)
            print("reminder day: " + reminderDay)
            print("reminder text: " + reminderText)
            db.events.insert_one({"username": username, "reminderName": reminderName, "reminderTime": reminderTime, "reminderDay": reminderDay, "reminderText":reminderText})
    result = db.events.find({"username": username})
    listEvents =[]
    #update so title can have spaces and really anything
    reminderNameRe = re.compile(r"u'reminderName': u'(.*)', u'reminderTime'")
    reminderNameRe2 = re.compile(r"u'reminderName': u\"(.*)\", u'reminderTime'")
    #consider " and '
    reminderTextRe1 = re.compile(r"u'reminderText': u'(.*)', u'reminderDay")
    reminderTextRe2 = re.compile(r"u'reminderText': u\"(.*)\", u'reminderDay")
    reminderDayRe = re.compile(r"u'reminderDay': u'(\d{4}-\d{2}-\d{2})', u'_id'")
    reminderTimeRe = re.compile(r"u'reminderTime': u'(\d{2}:\d{2})', u'reminderText':")
    for doc in result:
        eventStr=""
        matchName = reminderNameRe.search(str(doc))
        matchName2 = reminderNameRe2.search(str(doc))
        matchText1 = reminderTextRe1.search(str(doc))
        matchText2 = reminderTextRe2.search(str(doc))
        matchTime = reminderTimeRe.search(str(doc))
        matchDay = reminderDayRe.search(str(doc))
        if matchName is not None:
            print("one name: " + matchName.group(1))
            eventStr+=matchName.group(1) + ": "
        elif matchName2 is not None:
            print("two name: " + matchName2.group(1))
            eventStr+=matchName2.group(1) + ": "
        if matchText1 is not None:
            print("one text: " + matchText1.group(1))
            eventStr+=matchText1.group(1)
        elif matchText2 is not None:
            print("two text: " + matchText2.group(1))
            eventStr+=matchText2.group(1)
        if matchTime is not None:
            print(matchTime.group(1))
            time = re.compile("(\d{2}):(\d{2})")
            tm = time.search(matchTime.group(1))
            if int(tm.group(1)) < 12:
                eventStr+= "\n at " + matchTime.group(1) + "AM"
            else:
                hr = str(int(tm.group(1))-12)
                eventStr+= "\n at " + hr + ":" + tm.group(2) + "PM"
        if matchDay is not None:
            print(matchDay.group(1))
            eventStr+=" on " + matchDay.group(1)
        listEvents.append(eventStr)
    return render_template('loggedIn.html', events=listEvents, name=username)
        

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
