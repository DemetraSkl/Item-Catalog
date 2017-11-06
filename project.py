from flask import Flask, render_template, request, redirect
from flask import jsonify, url_for, flash, make_response
from sqlalchemy import create_engine, asc, func, distinct, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Category, Item
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
import requests
import string

from flask_wtf.csrf import CSRFProtect


app = Flask(__name__)

# CLIENT_ID will be used for Goodgle sign in
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPILICATION_NAME = "Recipe Ideas Application"

# Connect to database and create session
engine = create_engine('sqlite:///categoriesappwithusers.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token
# to secure connection b/w app server and client
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    # Check if client has the same state token as app server
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "Access token received %s" % access_token

    # Client secret and access_token (i.e. one-time-code)
    # is used for app server to obtain long-term access token
    app_id = json.loads(open
                        ('fb_client_secrets.json', 'r')
                        .read())['web']['app_id']
    app_secret = json.loads(open
                            ('fb_client_secrets.json', 'r')
                            .read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (  # noqa
           app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from FB API
    userinfo_url = "https://graph.facebook.com/v2.10/me"
    # The token needs to first be extracted from the result
    token = result.split(',')[0].split(':')[1].replace('"', '')
    # Use token to obtain name, id and email information
    url = 'https://graph.facebook.com/v2.10/me?access_token=%s&fields=name,id,email' % (  # noqa
           token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in login_session to be able to log out
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.10/me/picture?access_token=%s&redirect=0&height=200&width=200' % (  # noqa
           token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # Check if user exists using email address
    user_id = getUserID(login_session['email'])
    if not user_id:
        # Need to create new user
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    # Output welcome message to logged in user
    output = ''
    output += '<h2>Welcome, '
    output += login_session['username']
    output += '!</h2>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 100px; height: 100px;\
            border-radius: 150px;-webkit-border-radius: 150px;\
            -moz-border-radius: 150px;"> '
    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?\
            access_token=%s' % (facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "Current user not connected anymore."


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain one-time-code originating from Google API
    code = request.data

    try:
        # Exchange one-time-code for long-term access token
        # (i.e. credentials object)
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        # One-time-code will only be sent once
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check if the access token is valid
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # Abort in case of error
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('500')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that access token is for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID does not match given user ID"), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps("Current user is already connected."), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store valid access token
    # Necessary to log out and retrieve info from Google API
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    login_session['provider'] = 'google'

    # Check if user exists, otherwise make a new one
    user_id = getUserID(data['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h2>Welcome, '
    output += login_session['username']
    output += '!</h2>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 100px; height: 100px;\
                border-radius: 150px;\
                -webkit-border-radius: 150px;\
                -moz-border-radius: 150px;"> '
    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('acess_token')
    # Disconnect only connected users
    if access_token is None:
        response = make_response(
            json.dumps("Current user not connected"), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        # del login_session['access_token']
        # del login_session['gplus_id']
        # del login_session['username']
        # del login_session['email']
        # del login_session['picture']
        response = make_response(
            json.dumps("Successfully disconnected."), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(
            json.dumps("Failed to revoke user's token"), 400)
        response.headers['Content-Type'] = 'application/json'
        return response

# Disconnect and erase login_session data based on provider


@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            # del login_session['credentials']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
        del login_session['user_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['provider']
        del login_session['access_token']
        flash("You have successfully logged out.")
        return redirect(url_for('showLogin'))
    else:
        flash("You are still connected.")
        return redirect(url_for('showLogin'))

# Login helper functions


def createUser(login_session):
    newUser = User(
        name=login_session['username'],
        email=login_session['email'],
        picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# JSON APIs to view Category Information
@app.route('/catalog/<int:categoty_id>/JSON')
@app.route('/catalog/<int:categoty_id>/items/JSON')
def categoryJSON(category_id):
    category = session.query(Category).filter_by(id=category_id)
    items = session.query(Item).filter_by(category_id=category_id).all()
    return jsonify(CategoryItems=[i.serialize for i in items])


@app.route('/catalog/<int:category_id>/<int:item_id>/JSON')
def itemJSON(category_id, item_id):
    item = session.query(Item).filter_by(id=item_id).one()
    return jsonify(item=item.serialize)


@app.route('/catalog/JSON')
def catalogJSON():
    categories = session.query(Category).all()
    return jsonify(categories=[i.serialize for i in categories])

# Show main page


@app.route('/')
@app.route('/catalog')
def showCatalog():
    catalog = session.query(Category)
    recentItems = session.query(Item).order_by(Item.time.desc()).limit(5)
    # for i in recentItems:
    #     print i.time
    # print testItem.time
    # print "Helloooooo"
    # print recentItems
    return render_template(
        'catalog.html',
        catalog=catalog,
        recentItems=recentItems,
        is_category=False
        )

# Show category items


@app.route('/catalog/<int:category_id>')
@app.route('/catalog/<int:category_id>/items')
def showCategory(category_id):
    catalog = session.query(Category)
    category = session.query(Category).filter_by(id=category_id).one()
    creator = getUserInfo(category.user_id)
    items = session.query(Item).filter_by(category_id=category_id).all()
    itemNum = str(len(items))
    return render_template(
        'catalog.html',
        catalog=catalog,
        items=items,
        itemNum=itemNum,
        category=category,
        creator=creator,
        is_category=True
        )

# Show item information


@app.route('/catalog/<int:category_id>/<int:item_id>')
def showItem(category_id, item_id):
    category = session.query(Category).filter_by(id=category_id).one()
    item = session.query(Item).filter_by(id=item_id).one()
    creator = getUserInfo(item.user_id)
    # user = getUserInfo(login_session['user_id'])
    if ('username' not in login_session or
            creator.id != login_session['user_id']):
        return render_template(
            'item.html',
            item=item,
            category=category,
            isCreator=False
            )
    else:
        return render_template(
            'item.html',
            item=item,
            category=category,
            isCreator=True
            )

# Create new item


@app.route('/catalog/new', methods=['GET', 'POST'])
def newItem():
    if 'username' not in login_session:
        return redirect('/login')
    creator = getUserInfo(login_session['user_id'])
    if request.method == 'POST':
        # print "CATEGORY"
        # print request.form['category']
        # print "NAME:"
        # print request.form['name']
        # print "CRETATOR_ID"
        # print creator.id
        # print "DESCRIPTION:"
        # print request.form['description']
        newCategory = (session.query(Category)
                              .filter_by(name=request.form['category'])
                              .one())
        # print "Category ID:"
        # print newCategory.id
        newItem = Item(
            name=request.form['name'],
            description=request.form['description'],
    	    category_id=newCategory.id,
            user_id=creator.id
            )
        session.add(newItem)
        session.commit()
        flash('New %s Item Successfully Created' % (newItem.name))
        return redirect(url_for('showCatalog'))
    else:
        return render_template('newItem.html', creator=creator)

# Edit an item's information


@app.route(
    '/catalog/<int:category_id>/<int:item_id>/edit',
    methods=['GET', 'POST'])
def editItem(category_id, item_id):
    category = (session.query(Category)
                       .filter_by(id=category_id)
                       .one())
    editedItem = session.query(Item).filter_by(id=item_id).one()
    creator = getUserInfo(editedItem.user_id)
    if 'username' not in login_session:
        return redirect('/login')
    if creator.id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized\
                to edit this item. Please create your own item.');}</script>\
                <body onload='myFunction()'>"
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['category']:
            editedCategory = (session.query(Category)
                                     .filter_by(name=request.form['category'])
                                     .one())
            editedItem.category_id = editedCategory.id
            print "heyo"
        session.add(editedItem)
        session.commit()
        flash("Item Successfully Edited")
        return redirect(url_for('showCategory', category_id=category_id))
    else:
        return render_template(
            'editItem.html',
            item=editedItem,
            category=category,
            creator=creator
            )

# Delete item


@app.route(
    '/catalog/<int:category_id>/<int:item_id>/delete',
    methods=['GET', 'POST']
    )
def deleteItem(category_id, item_id):
    category = session.query(Category).filter_by(id=category_id).one()
    itemToDelete = session.query(Item).filter_by(id=item_id).one()
    print "The item To delete ID is"
    creator = getUserInfo(itemToDelete.user_id)
    if 'username' not in login_session:
        return redirect('/login')
    if creator.id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized \
                to delete this item. Please delete your own item.');}</script>\
                <body onload='myFunction()'>"
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Item Successfully Deleted')
        return redirect(url_for('showCategory', category_id=category_id))
    else:
        return render_template(
            'deleteItem.html',
            item=itemToDelete,
            category=category,
            creator=creator
            )


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
