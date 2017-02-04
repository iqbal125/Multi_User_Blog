#Controls main functionality of blog

import os
import webapp2
import jinja2
import re
import random
import string
import hashlib
import hmac
from google.appengine.ext import db


""" The Main Blog Handler Class and Methods """

#Used to make hashes more secure
secret = "xsw321"
#Used for connecting templates with jinja2
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
#Creates jinja2 environment for loading templates
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

#Renders templates with jinja2
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

#Returns a beginning value and a hmac value, to be used as a cookie in the Handler
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

#Makes sure hash values match
def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

#Basic request handling, slightly modified and copied from Udacity Intro to Backend course
class Handler(webapp2.RequestHandler):
    #Writes to webpage
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
    #Renders Jinja template
    def render_str(self, template, **kw):
        kw['user'] = self.user
        return render_str(template, **kw)
    #Writes template to webpage
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))
    #Sets cookie name and value in default path
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))
    #Returns the cookie beginning value after it macthes the secure value
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)
    #Sets cookie to user id from the Google App Engine Database
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))
    #Sets cookie to None
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
    #Reads cookie and sets user to that user id
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


""" Classes to Handle the Requests """

#Sorts posts on the home page by date created
class HomePage(Handler):
    def get(self):
        posts = db.GqlQuery("select * from Post order by created desc limit 10")
        self.render('home.html', posts = posts)

class LoginPage(Handler):
    def get(self):
        self.render("login.html")
    #Gets username and password
    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        #If valid username and password logs in user, otherwise prints error message
        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login.html', error = msg)

#Calls logout method in the Handler and redirects to homepage
class LogoutPage(Handler):
    def get(self):
        self.logout()
        self.redirect('/')

#Lets user submit a post if they are logged in
class NewPostPage(Handler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')
        #If there is subject and content, the Post class creates a new post and redirects to a permalink
        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "Subject and Content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)

class PostPage(Handler):
    def get(self, post_id):
        #Creates key for specific post
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        #Gets the key for a specific post
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post = post)

class SignupPage(Handler):
    def get(self):
        self.render("sign-up.html")

    def post(self):
        #Gets username, password, email
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)
        #Checks if username is valid otherwise returns error
        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(SignupPage):
    def done(self):
        #Makes sure user doesnt already exist, then creates and logs in new user
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('sign-up.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')


""" Makes password hashes """

#Generates 5 random letters for use in make_pw_hash method
def make_salt(length = 5):
    return ''.join(random.SystemRandom().choice(string.ascii_letters) for x in range(length))

#Generates and returns a secure hash value
def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

#Makes sure database hash matches user hash
def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

#Creates a users Key Object
def users_key(name):
    return db.Key.from_path('users', name)

#Creates a blog Key Object
def blog_key(group):
    return db.Key.from_path('blogs', group)


""" The User and Post Models """

#User entity with name, password hash and optional email properties
class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    #Returns a user by their id
    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid, parent = users_key())

    #Returns a user by their name
    @classmethod
    def by_name(cls, name):
        u = cls.all().filter('name =', name).get()
        return u

    #Returns a new user
    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return cls(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    #Looks up a user by name, and if the user is valid returns the user
    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


#Post entity with subject, content and created date properties
class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

    #Renders new posts
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)


""" Username and Password Validation """

#Basic valid username and password code, copied from Udacity Intro to Backend course
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)



""" Handles URI Routing """

app = webapp2.WSGIApplication([('/', HomePage),
                               ('/([0-9]+)', PostPage),
                               ('/newpost', NewPostPage),
                               ('/signup', Register),
                               ('/login', LoginPage),
                               ('/logout', LogoutPage)
                               ],
                              debug=True)
