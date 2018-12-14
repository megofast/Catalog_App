from flask import Flask, render_template, request, redirect
from flask import url_for, flash, jsonify, make_response
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base, Category, User, Item
from flask import session as login_session
import random, string, json, requests
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2

app = Flask(__name__)

CLIENT_ID = json.loads(open('client_secret.json', 'r').read())['web']['client_id']

# Connect to the database
engine = create_engine('sqlite:///itemscatalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind = engine)

user_data = {}

@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE = state)


@app.route('/gconnect', methods = ['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secret.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v2/tokeninfo?access_token=%s' % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')

    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        print stored_access_token
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v2/userinfo"
    #userinfo_url = "https://www.googleapis.com/plus/v1/people/me"
    params = {'access_token': credentials.access_token, 'alt': 'json'}

    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # Set the user data dictionary to contain username and picture
    user_data['username'] = login_session['username']
    user_data['picture'] = login_session['picture']

    # Check if the user is in the database already
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 50%; height: 50%; border-radius: 50%; -webkit-border-radius: 50%; -moz-border-radius: 50%;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output

@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Execute HTTP GET request to revoke current token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        # Reset all the users session variables
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['picture']
        del login_session['email']

        # Reset the user_data dictionary when the user logs out
        del user_data['username']
        del user_data['picture']

        flash('You have successfully logged out.')
        return redirect(url_for('catalog'))
    else:
        # The given token was invalid?
        flash('Failed to revoke the token, unable to logout.')
        return redirect(url_for('catalog'))


def getUserInfo(user_id):
    session = DBSession()
    user = session.query(User).filter_by(email = login_session['email']).one()
    return user.id


def getUserID(email):
    session = DBSession()
    try:
        user = session.query(User).filter_by(email = email).one()
        return user.id
    except:
        return None


def createUser(login_session):
    session = DBSession()
    newUser = User(name = login_session['username'],
                    email = login_session['email'],
                    picture = login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email = login_session['email']).one()
    return user.id

@app.route('/catalog')
def catalog():
    # This is the endpoint to show the itemscatalog
    session = DBSession()
    category_list = session.query(Category).all()
    # loop through category list and get total items in each category
    #category = session.query(Category).filter_by(name = category).one()
    category_totals = []
    for cat in category_list:
        category_totals.append(session.query(Item).filter_by(category = cat).count())

    recent_items = session.query(Item).order_by(Item.id.desc()).limit(3).all()

    if 'username' not in login_session:
        return render_template('catalog.html', categories = category_list,
                            items = recent_items, totals = category_totals,
                            selected = "Recently Added")
    else:
        # The user is logged in, show the user catalog page
        return render_template('catalog.html', categories = category_list,
                                items = recent_items, totals = category_totals,
                                user = user_data, selected = "Recently Added")

@app.route('/catalog/category', methods = ['GET', 'POST'])
def newCategory():
    # Check to see if the user is logged in or not
    if 'username' not in login_session:
        flash('You must be logged in to create a category.')
        return redirect('/login')
    session = DBSession()
    if request.method == 'POST':
        # Redirects back to the catalog page, form has been filled out
        try:
            if session.query(Category).filter_by(name = newItem.name).one():
                # Cannot have duplicate category names redirect back to form
                flash('Category already exists.')
                return render_template('new_category.html')
        except:
            # Get the user from the database
            user = session.query(User).filter_by(name = login_session['username']).one()
            if request.form['name']:
                newItem = Category(name = request.form['name'],
                                    user = user)
                session.add(newItem)
                session.commit()
                flash('New Category Added!')
                return redirect(url_for('catalog'))
            else:
                # The name is blank... Do not create a new item.
                flash('Cannot have a blank name.')
                return redirect(url_for('newCategory'))
    else:
        # GET request, Show page with form
        return render_template('new_category.html', user = user_data)


@app.route('/catalog/category/<string:category>')
def showCategory(category):
    # This is the endpoint to show the itemscatalog for specific category
    session = DBSession()
    category = session.query(Category).filter_by(name = category).one()
    category_list = session.query(Category).all()
    item_list = session.query(Item).filter_by(category = category)
    category_totals = []
    for cat in category_list:
        category_totals.append(session.query(Item).filter_by(category = cat).count())

    if 'username' not in login_session:
        return render_template('catalog.html', categories = category_list,
                            items = item_list, totals = category_totals,
                            selected = category.name)
    else:
        # The user is logged in, show the user catalog page
        return render_template('catalog.html', categories = category_list,
                                items = item_list, totals = category_totals,
                                user = user_data, selected = category.name)


@app.route('/catalog/category/<string:category>/edit', methods = ['GET', 'POST'])
def editCategory(category):
    # This method is for editing a category
    if 'username' not in login_session:
        flash('You must be logged in to edit a category.')
        return redirect(url_for('catalog'))
    else:
        # The user is logged in, proceed with edit
        session = DBSession()
        editItem = session.query(Category).filter_by(name = category).one()
        if editItem.user.name == login_session['username']:
            # The user owns this category, allow edit
            if request.method == 'POST':
                if request.form['name']:
                    editItem.name = request.form['name']
                    session.add(editItem)
                    session.commit()
                    flash('Edited Category ' + editItem.name + '!')
                    return redirect(url_for('catalog'))
                else:
                    flash('Failed to edit, you must fill out the form.')
                    return redirect('editCategory', category = category)
            else:
                return render_template('edit_category.html', category = category,
                                        user = user_data)
        else:
            # The user is logged in, but does not own the category
            flash('You do not have permission to edit this category.')
            return redirect(url_for('catalog'))


@app.route('/catalog/category/<string:category>/delete', methods = ['GET', 'POST'])
def deleteCategory(category):
    if 'username' not in login_session:
        # The user is not logged in and cannot delete Categories
        flash('You must be logged in to delete categories.')
        return redirect(url_for('catalog'))
    else:
        session = DBSession()
        deleteItem = session.query(Category).filter_by(name = category).one()
        # Check to make sure the logged in user is the owner of the category
        if (deleteItem.user.name == login_session['username']):
            if request.method == 'POST':
                session.delete(deleteItem)
                # Delete all the items in the category as well
                items = session.query(Item).filter_by(category = deleteItem).all()
                for item in items:
                    session.delete(item)
                session.commit()
                flash('Deleted ' + deleteItem.name + '!')
                return redirect(url_for('catalog'))
            else:
                return render_template('delete_category.html',
                                        category = category, user = user_data)
        else:
            # The user does not own this category and cannot delete it
            flash('Sorry, you do not have permission to delete this category.')
            return redirect(url_for('catalog'))


@app.route('/catalog/item/<int:item_id>')
def showDetails(item_id):
    session = DBSession()

    item = session.query(Item).filter_by(id = item_id).one()

    if 'username' not in login_session:
        return render_template('item_details.html', item = item)
    else:
        # The user is logged in, show the user catalog page
        return render_template('item_details.html', item = item,
                                user = user_data)

@app.route('/catalog/item', methods = ['GET', 'POST'])
def newItem():
    # Check to see if the user is logged in, if not redirect to login page
    if 'username' not in login_session:
        flash('You must be logged in to add items to the catalog.')
        return redirect('/login')
    session = DBSession()
    if request.method == 'POST':
        if request.form['name']:
            category = session.query(Category).filter_by(
                                            name = request.form['category']).one()
            user = session.query(User).filter_by(
                                        name = login_session['username']).one()
            item = Item(name = request.form['name'],
                        description = request.form['desc'],
                        user = user,
                        category = category)
            session.add(item)
            session.commit()
            flash('New catalog item added!')
            # Add code to send to page for that category
            return redirect(url_for('showCategory', category = category.name))
        else:
            # The name field is blank. Do not allow creation
            flash('You must fill out an item name.')
            return redirect(url_for('newItem'))
    else:
        category_list = session.query(Category).all()
        return render_template('new_item.html', categories = category_list,
                                user = user_data)


@app.route('/catalog/item/<int:item_id>/edit', methods = ['GET', 'POST'])
def editItem(item_id):
    # Check to see if the user is logged in, if not redirect to login page
    if 'username' not in login_session:
        flash('You must be logged in to edit items in the catalog.')
        return redirect('/login')
    session = DBSession()
    item = session.query(Item).filter_by(id = item_id).one()
    if item.user.name == login_session['username']:
        if request.method == 'POST':
            if request.form['name']:
                category = session.query(Category).filter_by(name = request.form['category']).one()
                item.name = request.form['name']
                item.description = request.form['desc']
                item.category = category
                session.add(item)
                session.commit()
                flash('Edited catalog item' + item.name + '!')
                return redirect(url_for('showCategory', category = category.name))
            else:
                # No name entered, retry
                flash('You must fill out a name to successfully edit an item.')
                return redirect(url_for('editItem', item_id = item.id))
        else:
            category_list = session.query(Category).all()
            return render_template('edit_item.html', categories = category_list,
                                    user = user_data, item = item)
    else:
        # The user is not the owner of the item
        flash('You do not own this item, you cannot edit it.')
        return redirect(url_for('catalog'))


@app.route('/catalog/item/<int:item_id>/delete', methods = ['GET', 'POST'])
def deleteItem(item_id):
    if 'username' not in login_session:
        # The user is not logged in and cannot delete Categories
        flash('You must be logged in to delete items.')
        return redirect(url_for('catalog'))
    else:
        session = DBSession()
        deleteItem = session.query(Item).filter_by(id = item_id).one()
        # Check to make sure the logged in user is the owner of the category
        if (deleteItem.user.name == login_session['username']):
            if request.method == 'POST':
                session.delete(deleteItem)
                session.commit()
                flash('Deleted ' + deleteItem.name + '!')
                return redirect(url_for('catalog'))
            else:
                return render_template('delete_item.html',
                                        item = deleteItem, user = user_data)
        else:
            # The user does not own this category and cannot delete it
            flash('Sorry, you do not have permission to delete this category.')
            return redirect(url_for('catalog'))


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
