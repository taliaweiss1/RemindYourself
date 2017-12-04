#!/usr/bin/env python3

#import relevant libraries
import sys, os
from twilio.rest import Client
import re
from flask import Flask, render_template, session, redirect, url_for, escape, request
from passlib.hash import sha256_crypt
from pymongo import MongoClient
from datetime import datetime
import threading
from threading import Thread
from time import time, sleep
from time import time

#create flask app
app = Flask(__name__)

#connect to database
client = MongoClient()
db = client.reminders

#twilio credentials
account_sid = "AC8ce6439ae954b6854c0116fbbf45b8be"
auth_token = "d8dfb003de3fbd07d7e00ade381c7561"
twilioClient = Client(account_sid, auth_token)
numberFrom = "+15162520096"

#this is our homepage
@app.route('/', methods=['GET', 'POST'])
def index():
    if "login" in request.form:
        return redirect(url_for('login'))
    elif "becomeUser" in request.form:
        return redirect(url_for('becomeUser'))
    else:
        return render_template('homepage.html')
    
#this is our login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    #if login button has been pressed
    if request.method == 'POST' and "login" in request.form:
        #check database for user and correct password
        username = request.form['username']
        password = request.form['password']
        #if the username and password inputs were filled out
        if username and password:
            if db.users.find_one({"username": username}):
                cursor = db.users.find_one({"username": username})
                saltedPass = cursor['password']
                phoneNum = cursor['phoneNumber']
                #query and confirm password correctness
                if sha256_crypt.verify(password, saltedPass):
                    #set session variables
                    session['username'] = request.form['username']
                    session['phoneNumber'] = phoneNum
                    return redirect(url_for('loggedIn'))
    if "back" in request.form:
        return redirect(url_for('index'))
    return render_template('login.html')

#this is our become user page
@app.route('/becomeUser', methods=['GET', 'POST'])
def becomeUser():
    #if become user button has been pressed
    if request.method == 'POST' and "becomeUser" in request.form:
        username = request.form['username']
        password = request.form['password']
        phoneNumber = request.form['phoneNumber']
        #if inputs have been filled out
        if username and password and phoneNumber:
            #make sure user doesn't exist
            if db.users.find({"username": username}).count() == 0:
                #check if valid phone number 
                regex = re.compile('\d{10}')
                match = regex.match(phoneNumber)
                if match is not None:
                    #if valid phone number salt, hash password and input in database
                    saltedPass = sha256_crypt.encrypt(password)
                    db.users.insert_one({"username": username, "password": saltedPass, "phoneNumber": phoneNumber})
                    session['username'] = username
                    session['phoneNumber'] = phoneNumber
                    return redirect(url_for('loggedIn'))
    if "back" in request.form:
        return redirect(url_for('index'))
    return render_template('becomeUser.html')

#this is our page for updating user information
@app.route('/updateInfo', methods=['GET', 'POST'])
def updateInfo():
    #update username form submission
    if "updateUser" in request.form:
        newUser = request.form['username']
        if newUser:
            db.users.update({"username": session['username']}, {"$set": {"username": newUser}})
            session['username'] = newUser
            return redirect(url_for('loggedIn'))
    #update phonenumber form submission
    if "updatePhone" in request.form:
        newPhone = request.form['phoneNumber']
        regex = re.compile('\d{10}')
        match = regex.match(newPhone)
        if match is not None:
            db.users.update({"username": session['username']}, {"$set": {"phoneNumber": newPhone}})
            session['phoneNumber'] = newPhone
            return redirect(url_for('loggedIn'))
    #update password form submission
    if "updatePass" in request.form:
        newPass = request.form['password']
        if newPass:
            newSaltedPass = sha256_crypt.encrypt(newPass)
            db.users.update({"username": session['username']}, {"$set": {"password": newSaltedPass}})
            return redirect(url_for('loggedIn'))
    if "back" in request.form:
        return redirect(url_for('loggedIn'))
    return render_template('editUser.html', name=session['username'], number=session['phoneNumber'])

#this is our edit reminder page
@app.route('/editReminder', methods=['GET', 'POST'])
def editReminder():
    #code to display events until line 160
    result = db.events.find({"username": session['username']})
    listEvents =[]
    #regex for title of event, text of event, date and time
    #takes into considersation strings with apostrophies
    reminderNameRe = re.compile(r"u'reminderName': u'(.*)', u'reminderTime'")
    reminderNameRe2 = re.compile(r"u'reminderName': u\"(.*)\", u'reminderTime'")
    #takes into considersation strings with apostrophies
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
            eventStr+=matchName.group(1) + ": "
        elif matchName2 is not None:
            eventStr+=matchName2.group(1) + ": "
        if matchText1 is not None:
            eventStr+=matchText1.group(1)
        elif matchText2 is not None:
            eventStr+=matchText2.group(1)
        if matchTime is not None:
            time = re.compile("(\d{2}):(\d{2})")
            tm = time.search(matchTime.group(1))
            if int(tm.group(1)) < 12:
                eventStr+= "\n at " + matchTime.group(1) + "AM"
            else:
                hr = str(int(tm.group(1))-12)
                eventStr+= "\n at " + hr + ":" + tm.group(2) + "PM"
        if matchDay is not None:
            eventStr+=" on " + matchDay.group(1)
        listEvents.append(eventStr)
    #update reminder button pressed
    if "updateReminder" in request.form:
        reminderName = request.form['reminderName']
        newReminderName = request.form['newReminderName']
        reminderDay = request.form['reminderDay']
        reminderTime = request.form['reminderTime']
        reminderText = request.form['reminderText']
        reminderTo = request.form['userTo']
        #if input is all filled out
        if reminderName and newReminderName and reminderDay and reminderTime and reminderText and reminderTo:
            #make sure the reminder exists
            if db.events.find({"username": session['username'], "reminderName": reminderName}).count() != 0:
                db.events.update({"username": session['username'], "reminderName": reminderName}, {"$set":{"username": reminderTo, "reminderName": newReminderName, "reminderTime": reminderTime, "reminderDay": reminderDay, "reminderText":reminderText}})
                return redirect(url_for('loggedIn')) 
    if "back" in request.form:
        return redirect(url_for('loggedIn'))
    listEvents = sorted(listEvents,key=str.lower)
    return render_template('editReminder.html', name=session['username'], events=listEvents)

#this is our page to delete reminders
@app.route('/deleteReminder', methods=['GET', 'POST'])
def deleteReminder():
    #code to display reminders until line 221
    result = db.events.find({"username": session['username']})
    listEvents =[]
    #regex for title of event, text of event, date and time
    #takes into considersation strings with apostrophies
    reminderNameRe = re.compile(r"u'reminderName': u'(.*)', u'reminderTime'")
    reminderNameRe2 = re.compile(r"u'reminderName': u\"(.*)\", u'reminderTime'")
    #takes into considersation strings with apostrophies
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
            eventStr+=matchName.group(1) + ": "
        elif matchName2 is not None:
            eventStr+=matchName2.group(1) + ": "
        if matchText1 is not None:
            eventStr+=matchText1.group(1)
        elif matchText2 is not None:
            eventStr+=matchText2.group(1)
        if matchTime is not None:
            time = re.compile("(\d{2}):(\d{2})")
            tm = time.search(matchTime.group(1))
            if int(tm.group(1)) < 12:
                eventStr+= "\n at " + matchTime.group(1) + "AM"
            else:
                hr = str(int(tm.group(1))-12)
                eventStr+= "\n at " + hr + ":" + tm.group(2) + "PM"
        if matchDay is not None:
            eventStr+=" on " + matchDay.group(1)
        listEvents.append(eventStr)
    #if delete reminder button has been pressed
    if "deleteReminder" in request.form:
        reminderName = request.form['reminderName']
        #if inputs have been filled out
        if reminderName:
            #make sure reminder exists
            if db.events.find({"username": session['username'], "reminderName": reminderName}).count() != 0:
                db.events.remove({"username": session['username'], "reminderName": reminderName})
                return redirect(url_for('loggedIn')) 
    if "back" in request.form:
        return redirect(url_for('loggedIn'))
    listEvents = sorted(listEvents,key=str.lower)
    return render_template('deleteReminder.html', name=session['username'],events=listEvents)

#this is our logged in page
@app.route('/loggedIn', methods=['GET', 'POST'])
def loggedIn():
    username = session['username']
    #logout if logout pressed
    if "logout" in request.form:
        return redirect(url_for('logout'))
    if "editInfo" in request.form:
        return redirect(url_for('updateInfo'))
    if "editReminder" in request.form:
        return redirect(url_for('editReminder'))
    if "deleteReminder" in request.form:
        return redirect(url_for('deleteReminder'))
    #code for displaying events until line 294
    result = db.events.find({"username": username})
    listEvents =[]
    #regex for title of event, text of event, date and time
    #takes into considersation strings with apostrophies
    reminderNameRe = re.compile(r"u'reminderName': u'(.*)', u'reminderTime'")
    reminderNameRe2 = re.compile(r"u'reminderName': u\"(.*)\", u'reminderTime'")
    #takes into considersation strings with apostrophies
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
        eventName=""
        timeArr=[]
        if matchName is not None:
            eventStr+=matchName.group(1) + ": "
            eventName =matchName.group(1)
        elif matchName2 is not None:
            eventStr+=matchName2.group(1) + ": "
            eventName=matchName2.group(1)
        if matchText1 is not None:
            eventStr+=matchText1.group(1)
        elif matchText2 is not None:
            eventStr+=matchText2.group(1)
        if matchDay is not None:
            eventStr+=" on " + matchDay.group(1)
        if matchTime is not None:
            time = re.compile("(\d{2}):(\d{2})")
            tm = time.search(matchTime.group(1))
            if int(tm.group(1)) < 12:
                eventStr+= "\n at " + matchTime.group(1) + "AM"
            else:
                hr = str(int(tm.group(1))-12)
                eventStr+= "\n at " + hr + ":" + tm.group(2) + "PM"
        listEvents.append(eventStr)
    sortedEvents = []
    listEvents = sorted(listEvents,key=str.lower)
    #code to list websites users unit line 302
    userList = db.users.find()
    users = []
    for user in userList:
        name = re.compile(r"u'username': u'(.*)', u'password'")
        userToAdd = name.search(str(user))
        if userToAdd is not None:
            if str(userToAdd.group(1)) != session['username']:
                users.append(userToAdd.group(1))
    #if add friend button has been pressed
    if "addFriend" in request.form:
        friend = request.form['userToAdd']
        #if input has been filled
        if friend:
            #make sure person is a user
            if db.users.find_one({"username": friend}):
                #make sure they aren't already friends
                if db.friends.find({"username": username, "friend": friend}).count() == 0:
                    #make sure the opposite request doesnt exists
                    if db.requests.find({"usernameFrom": username, "friend": friend}).count()==0:
                        #add to requests
                        db.requests.insert_one({"usernameFrom": username, "friend": friend})
        return redirect(url_for('loggedIn'))
    #code to display friend requests until line 325
    requestList = db.requests.find({"friend": username})
    requests = []
    friends = []
    friendRequestRe = re.compile(r"u'usernameFrom': u'(.*)', u'friend':")
    for friendRequest in requestList:
        matchFriend = friendRequestRe.search(str(friendRequest))
        if matchFriend is not None:
            requests.append(matchFriend.group(1))
    #if accept friend request button pressed
    if "acceptFriend" in request.form:
        friendAccept = request.form['userToAccept']
        #if input filled out
        if friendAccept:
            #make sure the request exists
            if db.requests.find({"usernameFrom": friendAccept, "friend": session['username']}).count() > 0:
                #add friends both ways into database
                db.friends.insert_one({"username": session['username'], "friend": friendAccept})
                db.friends.insert_one({"username": friendAccept, "friend": session['username']})
                #remove the request
                db.requests.remove({"usernameFrom": friendAccept, "friend": session['username']})
                requests.remove(friendAccept)
                msgString1 = "You and " + friendAccept + " are now friends"
                msgString2 = "You and " + session['username'] + " are now friends"
                getNum = db.users.find_one({"username": friendAccept})
                sendNum = getNum['phoneNumber']
                #alert users by text they are now friends
                sendMessage(session['phoneNumber'], msgString1)
                sendMessage(sendNum, msgString2)
    #code to display friends until line 352
    friendRe = re.compile(r", u'friend': u'(.*)'")
    friendList = db.friends.find({"username": username})
    for friendReal in friendList:
        matchFriend = friendRe.search(str(friendReal))
        if matchFriend is not None:
            friends.append(matchFriend.group(1))
    #if create reminder button pressed
    if "createReminder" in request.form:
        #following code makes sure the reminder isnt in the past, and adds it to the database if it isn't until line 431
        reminderName = request.form['reminderName']
        reminderDay = request.form['reminderDay']
        reminderTime = request.form['reminderTime']
        reminderText = request.form['reminderText']
        reminderTo = request.form['userTo']
        timeNow = datetime.now()
        nowDay = timeNow.day
        if nowDay < 10:
            nowDay = "0" + str(nowDay)
        nowMonth = timeNow.month
        if nowMonth < 10:
            nowMonth = "0" + str(nowMonth)
        nowYear = timeNow.year
        nowHour = timeNow.hour
        if nowHour < 10:
            nowHour = "0" + str(nowHour)
        nowMinute = timeNow.minute
        if nowMinute < 10:
            nowMinute = "0" + str(nowMinute)
        regTime = re.compile(r"(\d{2}):(\d{2})")
        regDay = re.compile(r"(\d{4})-(\d{2})-(\d{2})")
        createTime = regTime.search(reminderTime)
        createHr = ""
        createMin = ""
        if createHr is not None:
            createHr = createTime.group(1)
            createMin = createTime.group(2)
        createDate = regDay.search(reminderDay)
        createYear = ""
        createMonth = ""
        createDay = ""
        if createDate is not None:
            createYear = createDate.group(1)
            createMonth = createDate.group(2)
            createDay = createDate.group(3)
        #if not past the year
        if int(createYear) > int(nowYear):
            if reminderName and reminderTime and reminderDay and reminderText and reminderTo:
                if reminderTo == session['username']:
                    db.events.insert_one({"username": reminderTo, "reminderName": reminderName, "reminderTime": reminderTime, "reminderDay": reminderDay, "reminderText":reminderText})
                else:
                    for friend in friends:
                        if friend == reminderTo:
                            db.events.insert_one({"username": reminderTo, "reminderName": reminderName, "reminderTime": reminderTime, "reminderDay": reminderDay, "reminderText":reminderText})
        elif int(createYear) == int(nowYear) and int(createMonth) > int(nowMonth):
            if reminderName and reminderTime and reminderDay and reminderText and reminderTo:
                if reminderTo == session['username']:
                    db.events.insert_one({"username": reminderTo, "reminderName": reminderName, "reminderTime": reminderTime, "reminderDay": reminderDay, "reminderText":reminderText})
                else:
                    for friend in friends:
                        if friend == reminderTo:
                            db.events.insert_one({"username": reminderTo, "reminderName": reminderName, "reminderTime": reminderTime, "reminderDay": reminderDay, "reminderText":reminderText})
        elif int(createYear) == int(nowYear) and int(createMonth) == int(nowMonth) and int(createDay) > int(nowDay):
            if reminderName and reminderTime and reminderDay and reminderText and reminderTo:
                if reminderTo == session['username']:
                    db.events.insert_one({"username": reminderTo, "reminderName": reminderName, "reminderTime": reminderTime, "reminderDay": reminderDay, "reminderText":reminderText})
                else:
                    for friend in friends:
                        if friend == reminderTo:
                            db.events.insert_one({"username": reminderTo, "reminderName": reminderName, "reminderTime": reminderTime, "reminderDay": reminderDay, "reminderText":reminderText})
        elif int(createYear) == int(nowYear) and int(createMonth) == int(nowMonth) and int(createDay) == int(nowDay) and int(createHr) > int(nowHour):
            if reminderName and reminderTime and reminderDay and reminderText and reminderTo:
                if reminderTo == session['username']:
                    db.events.insert_one({"username": reminderTo, "reminderName": reminderName, "reminderTime": reminderTime, "reminderDay": reminderDay, "reminderText":reminderText})
                else:
                    for friend in friends:
                        if friend == reminderTo:
                            db.events.insert_one({"username": reminderTo, "reminderName": reminderName, "reminderTime": reminderTime, "reminderDay": reminderDay, "reminderText":reminderText})
        elif int(createYear) == int(nowYear) and int(createMonth) == int(nowMonth) and int(createDay) == int(nowDay) and int(createHr) == int(nowHour) and int(createMin) > int(nowMinute):
            if reminderName and reminderTime and reminderDay and reminderText and reminderTo:
                if reminderTo == session['username']:
                    db.events.insert_one({"username": reminderTo, "reminderName": reminderName, "reminderTime": reminderTime, "reminderDay": reminderDay, "reminderText":reminderText})
                else:
                    for friend in friends:
                        if friend == reminderTo:
                            db.events.insert_one({"username": reminderTo, "reminderName": reminderName, "reminderTime": reminderTime, "reminderDay": reminderDay, "reminderText":reminderText})
        return redirect(url_for('loggedIn'))
    return render_template('loggedIn.html', events=listEvents, name=session['username'], users=users, friends=friends, requests = requests)
        
#logout function
@app.route('/logout', methods=['GET', 'POST'])
def logout():
    # remove the username from the session if it's there
    session.pop('username', None)
    return redirect(url_for('index'))


# set the secret key.  keep this really secret:
app.secret_key = 'A0Zr98j/3yX R~XHH!jmN]LWX/,?RT'

#send message function
def sendMessage(numberTo, body):
    message = twilioClient.messages.create(
        to=numberTo,
        from_=numberFrom,
        body=body
    )

#funciton to run the application
def run():
    print("running")
    app.run(host='0.0.0.0', port=3456)

#function to delete a message
def deleteMsg(usr, title):
    db.events.remove({"username":usr, "reminderName":title})
   
#function to constantly query database and send relevent reminders, deletes reminder after text is sent 
def messages():
    while True:
        now = datetime.now()
        day = now.day
        if day < 10:
            day = "0" + str(day)
        month = now.month
        if month < 10:
            month = "0" + str(month)
        year = now.year
        hour = now.hour
        if hour < 10:
            hour = "0" + str(hour)
        minute = now.minute
        if minute < 10:
            minute = "0" + str(minute)
        reminderNow = db.events.find({"reminderTime": str(hour)+":"+str(minute), "reminderDay": str(year)+"-"+str(month)+"-"+str(day)})
        if reminderNow.count() > 0:
            reminderNameReFun = re.compile(r"u'reminderName': u'(.*)', u'reminderTime'")
            reminderNameRe2Fun = re.compile(r"u'reminderName': u\"(.*)\", u'reminderTime'")
            #takes into considersation strings with apostrophies
            reminderTextRe1Fun = re.compile(r"u'reminderText': u'(.*)', u'reminderDay")
            reminderTextRe2Fun = re.compile(r"u'reminderText': u\"(.*)\", u'reminderDay")
            usernameRe1 = re.compile(r"u'username': u'(.*)', u'reminderName'")
            usernameRe2 = re.compile(r"u'username': u\"(.*)\", u'reminderName'")
            for reminderResult in reminderNow:
                #username 
                reminderNameFun=usernameRe1.search(str(reminderResult))
                reminderUser=""
                if reminderNameFun is not None:
                    reminderUser = reminderNameFun.group(1)            
                else:
                    reminderNameFun=usernameRe2.search(str(reminderResult))
                    reminderUser=reminderNameFun.group(1)
                phoneNum = ""
                usernameQuery = db.users.find_one({"username":reminderUser})
                if usernameQuery is not None:
                    phoneNum = usernameQuery['phoneNumber']
                titleReminderSearch = reminderNameReFun.search(str(reminderResult))
                title=""
                if titleReminderSearch is not None:
                    title=titleReminderSearch.group(1)
                else:
                    titleReminderSearch=reminderNameRe2Fun.search(str(reminderResult))
                    title=titleReminderSearch.group(1)
                bodyReminderSearch = reminderTextRe1Fun.search(str(reminderResult))
                body=""
                if bodyReminderSearch is not None:
                    body = bodyReminderSearch.group(1)
                else:
                    bodyReminderSearch= reminderTextRe2Fun.search(str(reminderResult))
                    body=bodyReminderSearch.group(1)
                msg = title+" : "+body
                phoneNum="+1"+phoneNum
                sendMessage(phoneNum, msg)
                deleteMsg(reminderUser, title)


if __name__ == "__main__":
    #threads so that the application runs simultaneously with messages function 
    Thread(target = run).start()
    Thread(target = messages).start()
 
