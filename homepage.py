#!/usr/bin/env python3
import sys, os
from twilio.rest import Client
#regex
import re
from flask import Flask, render_template, session, redirect, url_for, escape, request
from passlib.hash import sha256_crypt
from pymongo import MongoClient
from datetime import datetime
import threading
from threading import Thread

app = Flask(__name__)
client = MongoClient()
db = client.reminders
account_sid = "AC8ce6439ae954b6854c0116fbbf45b8be"
auth_token = "d8dfb003de3fbd07d7e00ade381c7561"
twilioClient = Client(account_sid, auth_token)
numberFrom = "+15162520096"

@app.route('/', methods=['GET', 'POST'])
def index():
    if "login" in request.form:
        return redirect(url_for('login'))
    elif "becomeUser" in request.form:
        return redirect(url_for('becomeUser'))
    elif 'username' in session:
        return redirect(url_for('loggedIn'))
    else:
        return render_template('homepage.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST' and "login" in request.form:
        #check database for user and correct password
        username = request.form['username']
        password = request.form['password']
        if username and password:
            if db.users.find_one({"username": username}):
                cursor = db.users.find_one({"username": username})
                saltedPass = cursor['password']
                phoneNum = cursor['phoneNumber']
                if sha256_crypt.verify(password, saltedPass):
                    session['username'] = request.form['username']
                    session['phoneNumber'] = phoneNum
                    return redirect(url_for('loggedIn'))
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

@app.route('/updateInfo', methods=['GET', 'POST'])
def updateInfo():
    if "updateUser" in request.form:
        newUser = request.form['username']
        if newUser:
            db.users.update({"username": session['username']}, {"$set": {"username": newUser}})
            session['username'] = newUser
            return redirect(url_for('loggedIn'))
    if "updatePhone" in request.form:
        newPhone = request.form['phoneNumber']
        regex = re.compile('\d{10}')
        match = regex.match(newPhone)
        if match is not None:
            db.users.update({"username": session['username']}, {"$set": {"phoneNumber": newPhone}})
            session['phoneNumber'] = newPhone
            return redirect(url_for('loggedIn'))
    if "updatePass" in request.form:
        newPass = request.form['password']
        if newPass:
            newSaltedPass = sha256_crypt.encrypt(newPass)
            db.users.update({"username": session['username']}, {"$set": {"password": newSaltedPass}})
            return redirect(url_for('loggedIn'))
    if "back" in request.form:
        return redirect(url_for('index'))
    return render_template('editUser.html', name=session['username'], number=session['phoneNumber'])

@app.route('/editReminder', methods=['GET', 'POST'])
def editReminder():
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
    if "updateReminder" in request.form:
        reminderName = request.form['reminderName']
        newReminderName = request.form['newReminderName']
        reminderDay = request.form['reminderDay']
        reminderTime = request.form['reminderTime']
        reminderText = request.form['reminderText']
        reminderTo = request.form['userTo']
        if reminderName and newReminderName and reminderDay and reminderTime and reminderText and reminderTo:
            if db.events.find({"username": session['username'], "reminderName": reminderName}).count() != 0:
                db.events.update({"username": session['username'], "reminderName": reminderName}, {"$set":{"username": reminderTo, "reminderName": newReminderName, "reminderTime": reminderTime, "reminderDay": reminderDay, "reminderText":reminderText}})
                return redirect(url_for('loggedIn')) 
    if "back" in request.form:
        return redirect(url_for('index'))      
    return render_template('editReminder.html', name=session['username'], events=listEvents)

@app.route('/deleteReminder', methods=['GET', 'POST'])
def deleteReminder():
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
    if "deleteReminder" in request.form:
        reminderName = request.form['reminderName']
        if reminderName:
            if db.events.find({"username": session['username'], "reminderName": reminderName}).count() != 0:
                db.events.remove({"username": session['username'], "reminderName": reminderName})
                return redirect(url_for('loggedIn')) 
    if "back" in request.form:
        return redirect(url_for('index'))      
    return render_template('deleteReminder.html', name=session['username'],events=listEvents)

@app.route('/loggedIn', methods=['GET', 'POST'])
def loggedIn():
    username = session['username']
    if "logout" in request.form:
        return redirect(url_for('logout'))
    if "editInfo" in request.form:
        return redirect(url_for('updateInfo'))
    if "editReminder" in request.form:
        return redirect(url_for('editReminder'))
    if "deleteReminder" in request.form:
        return redirect(url_for('deleteReminder'))
     #check current time to get rid of old reminders
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
    getRidReminders = db.events.find({"username":session['username']})
    if getRidReminders.count() > 0:
        getRidReminderName = re.compile(r"u'reminderName': u'(.*)', u'reminderTime'")
        getRidReminderName2 = re.compile(r"u'reminderName': u\"(.*)\", u'reminderTime'")
        getRidUser1 = re.compile(r"u'username': u'(.*)', u'reminderName'")
        getRidUser2 = re.compile(r"u'username': u\"(.*)\", u'reminderName'")
        getRidDate = re.compile(r"u'reminderDay': u'(\d{4})-(\d{2})-(\d{2})', u'_id'")
        getRidTime = re.compile(r"u'reminderTime': u'(\d{2}):(\d{2})', u'reminderText':")
        for ridReminder in getRidReminders:
            ridDate = getRidDate.search(str(ridReminder))
            ridDay=""
            ridMonth=""
            ridyear=""
            ridHour=""
            ridMinute = ""
            if ridDate is not None:
                ridDay = ridDate.group(3)
                ridMonth = ridDate.group(2)
                ridYear = ridDate.group(1)
            ridTime = getRidTime.search(str(ridReminder))
            if ridTime is not None:
                ridHour = ridTime.group(1)
                ridMinute = ridTime.group(2)
            #if past the year
            if int(ridYear) < int(nowYear):
                #get rid
                #username 
                ridReminderUser=getRidUser1.search(str(ridReminder))
                reminderUserGetRid=""
                if ridReminderUser is not None:
                    reminderUserGetRid = ridReminderUser.group(1)            
                else:
                    ridReminderUser=getRidUser2.search(str(ridReminder))
                    reminderUserGetRid=ridReminderUser.group(1)
                ridTitleReminder = getRidReminderName.search(str(ridReminder))
                reminderTitleGetRid=""
                if ridTitleReminder is not None:
                    reminderTitleGetRid=ridTitleReminder.group(1)
                else:
                    ridTitleReminder=getRidReminderName2.search(str(ridReminder))
                    reminderTitleGetRid = ridTitleReminder.group(1)
                db.events.remove({"username":reminderUserGetRid, "reminderName":reminderTitleGetRid})
            #is same year and past month or same month and past the day
            elif int(ridYear) == int(nowYear) and int(ridMonth) < int(nowMonth):
                #username 
                ridReminderUser=getRidUser1.search(str(ridReminder))
                reminderUserGetRid=""
                if ridReminderUser is not None:
                    reminderUserGetRid = ridReminderUser.group(1)            
                else:
                    ridReminderUser=getRidUser2.search(str(ridReminder))
                    reminderUserGetRid=ridReminderUser.group(1)
                ridTitleReminder = getRidReminderName.search(str(ridReminder))
                reminderTitleGetRid=""
                if ridTitleReminder is not None:
                    reminderTitleGetRid=ridTitleReminder.group(1)
                else:
                    ridTitleReminder=getRidReminderName2.search(str(ridReminder))
                    reminderTitleGetRid = ridTitleReminder.group(1)
                db.events.remove({"username":reminderUserGetRid, "reminderName":reminderTitleGetRid})
            elif int(ridYear) == int(nowYear) and int(ridMonth) == int(nowMonth) and int(ridDay) < int(nowDay):
                #get rid
                #username 
                ridReminderUser=getRidUser1.search(str(ridReminder))
                reminderUserGetRid=""
                if ridReminderUser is not None:
                    reminderUserGetRid = ridReminderUser.group(1)            
                else:
                    ridReminderUser=getRidUser2.search(str(ridReminder))
                    reminderUserGetRid=ridReminderUser.group(1)
                ridTitleReminder = getRidReminderName.search(str(ridReminder))
                reminderTitleGetRid=""
                if ridTitleReminder is not None:
                    reminderTitleGetRid=ridTitleReminder.group(1)
                else:
                    ridTitleReminder=getRidReminderName2.search(str(ridReminder))
                    reminderTitleGetRid = ridTitleReminder.group(1)
                db.events.remove({"username":reminderUserGetRid, "reminderName":reminderTitleGetRid})
            #if same year, month, day and past hour
            elif int(ridYear) == int(nowYear) and int(ridMonth) == int(nowMonth) and int(ridDay) == int(nowDay) and int(ridHour)<int(nowHour):
                #get rid
                #username 
                ridReminderUser=getRidUser1.search(str(ridReminder))
                reminderUserGetRid=""
                if ridReminderUser is not None:
                    reminderUserGetRid = ridReminderUser.group(1)            
                else:
                    ridReminderUser=getRidUser2.search(str(ridReminder))
                    reminderUserGetRid=ridReminderUser.group(1)
                ridTitleReminder = getRidReminderName.search(str(ridReminder))
                reminderTitleGetRid=""
                if ridTitleReminder is not None:
                    reminderTitleGetRid=ridTitleReminder.group(1)
                else:
                    ridTitleReminder=getRidReminderName2.search(str(ridReminder))
                    reminderTitleGetRid = ridTitleReminder.group(1)
                db.events.remove({"username":reminderUserGetRid, "reminderName":reminderTitleGetRid})
            #if same day, month, year and hour but past minute
            elif int(ridYear) == int(nowYear) and int(ridMonth) == int(nowMonth) and int(ridDay) == int(nowDay) and int(ridHour) == int(nowHour) and int(ridMinute) < int(nowMinute):
                #get rid
                #username 
                ridReminderUser=getRidUser1.search(str(ridReminder))
                reminderUserGetRid=""
                if ridReminderUser is not None:
                    reminderUserGetRid = ridReminderUser.group(1)            
                else:
                    ridReminderUser=getRidUser2.search(str(ridReminder))
                    reminderUserGetRid=ridReminderUser.group(1)
                ridTitleReminder = getRidReminderName.search(str(ridReminder))
                reminderTitleGetRid=""
                if ridTitleReminder is not None:
                    reminderTitleGetRid=ridTitleReminder.group(1)
                else:
                    ridTitleReminder=getRidReminderName2.search(str(ridReminder))
                    reminderTitleGetRid = ridTitleReminder.group(1)
                db.events.remove({"username":reminderUserGetRid, "reminderName":reminderTitleGetRid})
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
    userList = db.users.find()
    users = []
    for user in userList:
        name = re.compile(r"u'username': u'(.*)', u'password'")
        userToAdd = name.search(str(user))
        if userToAdd is not None:
            if str(userToAdd.group(1)) != session['username']:
                users.append(userToAdd.group(1))
    if "addFriend" in request.form:
        friend = request.form['userToAdd']
        if friend:
            if db.users.find_one({"username": friend}):
                if db.friends.find({"username": session['username'], "friend": friend}).count() == 0:
                    db.friends.insert_one({"username": username, "friend": friend})
        return redirect(url_for('loggedIn'))
    friendList = db.friends.find({"username": session['username']})
    friends = []
    friendRe = re.compile(r"u'friend': u'(.*)'}")
    for friend in friendList:
        matchFriend = friendRe.search(str(friend))
        if matchFriend is not None:
            friends.append(matchFriend.group(1))
    if "createReminder" in request.form:
        reminderName = request.form['reminderName']
        reminderDay = request.form['reminderDay']
        reminderTime = request.form['reminderTime']
        reminderText = request.form['reminderText']
        reminderTo = request.form['userTo']
        if reminderName and reminderTime and reminderDay and reminderText and reminderTo:
            if reminderTo == session['username']:
                db.events.insert_one({"username": reminderTo, "reminderName": reminderName, "reminderTime": reminderTime, "reminderDay": reminderDay, "reminderText":reminderText})
            else:
                for friend in friends:
                    if friend == reminderTo:
                        db.events.insert_one({"username": reminderTo, "reminderName": reminderName, "reminderTime": reminderTime, "reminderDay": reminderDay, "reminderText":reminderText})
        return redirect(url_for('loggedIn'))
    return render_template('loggedIn.html', events=listEvents, name=session['username'], users=users, friends=friends)
        

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    # remove the username from the session if it's there
    session.pop('username', None)
    return redirect(url_for('index'))


# set the secret key.  keep this really secret:
app.secret_key = 'A0Zr98j/3yX R~XHH!jmN]LWX/,?RT'

def sendMessage(numberTo, body):
    message = twilioClient.messages.create(
        to=numberTo,
        from_=numberFrom,
        body=body
    )
    
def run():
    print("running")
    app.run(host='0.0.0.0', port=3456)

def messages():
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


if __name__ == "__main__":
    Thread(target = run).start()
    Thread(target = messages).start()
