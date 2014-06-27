import os
import webapp2
import jinja2
import cgi
import re
import hashlib
import json
import random
import string
import datetime
import time
import  logging

from google.appengine.api import memcache
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(length))


def escape_html(s):
    return cgi.escape(s, quote=True)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")


def valid_username(username):
    return USER_RE.match(username)


def valid_password(password):
    return PASSWORD_RE.match(password)


def valid_email(email):
    return EMAIL_RE.match(email) or not email


def hash_str(s):
        return hashlib.md5(s).hexdigest()


def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))


def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
            return val


class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def render_json(self, d):
        json_txt = json.dumps(d)
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        self.write(json_txt)

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        if self.request.url.endswith('.json'):
            self.format = 'json'
        else:
            self.format = 'html'


class User(db.Model):
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.StringProperty(required=False)


class SignupHandler(BlogHandler):

    def render_front(self, username="", password="", verify="", email="",
                     username_error="", password_error="", verify_error="", email_error=""):
        self.render("signup.html", username=username, password=password, verify=verify, email=email,
                    username_error=username_error, password_error=password_error,
                    verify_error=verify_error, email_error=email_error)

    def get(self):
        self.render("signup.html")

    def post(self):
        user_username = self.request.get('username')
        user_password = self.request.get('password')
        user_verify = self.request.get('verify')
        user_email = self.request.get('email')

        user_name = escape_html(user_username)
        user_pass = escape_html(user_password)
        pass_verify = escape_html(user_verify)
        email_id = escape_html(user_email)

        username_error = ""
        password_error = ""
        verify_error = ""
        email_error = ""

        error = False

        if not valid_username(user_username):
            username_error = "That's not a valid Username!"
            error = True

        if not valid_password(user_password):
            password_error = "That's not a valid password!"
            error = True

        if not user_verify or not user_password == user_verify:
            verify_error = "Passwords do not match"
            error = True

        if not valid_email(user_email):
            email_error = "That's not a valid email!"
            error = True

        if error:
            self.render("signup.html", username=user_name, email=email_id, username_error=username_error,
                        password_error=password_error, verify_error=verify_error, email_error=email_error)

        else:
            b = User(username=user_username, password=user_password, email=user_email)
            b.put()
            self.response.headers.add_header('Set-Cookie', 'user_name=%s; Path=/' % str(user_name))
            self.redirect("/welcome")


class LoginHandler(BlogHandler):

    def get(self):
        self.render("login.html")

    def post(self):

        user_valid = self.request.get("username")
        pass_valid = self.request.get("password")
        valid_login = User.all().filter("username =", user_valid).get()
        error = ""
        if valid_login and user_valid == valid_login.username and pass_valid == valid_login.password:
            self.response.headers.add_header('Set-Cookie', 'user_name=%s; Path=/' % str(user_valid))
            self.redirect("/welcome")
        else:
            error = "That's not a valid Login"
        self.render("login.html", error=error, valid_login=valid_login)


class LogoutHandler(BlogHandler):
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def get(self):
        self.logout()
        self.redirect('/blog/signup')


class Content(db.Model):
    title = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def as_dict(self):
        time_fmt = '%c'
        d = {'title': self.title,
             'content': self.content,
             'created': self.created.strftime(time_fmt),
             'last_modified': self.last_modified.strftime(time_fmt)}
        return d


class BlogFront(BlogHandler):
    def get(self):
        posts = Content.all().order('-created')
        if self.format == 'html':
            self.render('front.html', posts=posts)
        else:
            return self.render_json([p.as_dict() for p in posts])


class WelcomeHandler(webapp2.RequestHandler):
    def get(self):
        username = self.request.cookies.get("user_name")
        self.response.out.write("Welcome %s" % username)


def age_set(key, val):
    save_time = datetime.datetime.utcnow()
    memcache.set(key, (val, save_time))
    return save_time


def age_get(key):
    r = memcache.get(key)
    if r:
        print r
        val, save_time = r
        age = (datetime.datetime.utcnow() - save_time).total_seconds()
        return val, age
    else:
        return None, 0


def top_arts(update=False):

    mc_key = "top_blogs"
    contents, age = age_get(mc_key)
    print contents, age
    logging.error("DB QUERY")
    print "hello"
    if update or not contents:
        print "no"
        q = Content.all().order('-created')
        contents = list(q)
        print contents
        age = age_set(mc_key, contents)
        age = (datetime.datetime.utcnow() - age).total_seconds()
    return contents, age


class MainPage(BlogHandler):

    def get(self):
        contents, age = top_arts()
        if self.format == 'html':
            return self.render("posting.html", contents=contents, age=age_str(age))


class Perma(BlogHandler):
    def get(self, post_id):
        post_key = 'POST_' + post_id
        print post_key
        post, age = age_get(post_key)
        print "i am here"
        if not post:
            post = Content.get_by_id(int(post_id))
            age_set(post_key, post)
            age = 0
            print age


        if self.format == 'html':
            self.render("Blogpost.html", post=post, age=age_str(age))
            print "hello"
        else:
            self.render_json(post.as_dict())
            print "hello"


class Flush(BlogHandler):
    def get(self):
        clear_all = memcache.flush_all()
        if clear_all:
            self.write("Flushed")
            self.redirect("/blog")
        else:
            return "error"


class Newpost(BlogHandler):
    def get(self):
        self.render("front.html")

    def render_post(self, title="", content="", error=""):
        self.render("front.html", title=title, content=content, error=error)

    def post(self):
        title = self.request.get("subject")
        content = self.request.get("content")

        if title and content:
            a = Content(title=title, content=content)
            a.put()
            self.redirect('/blog/%s' % str(a.key().id()))
            print "redirected"
        else:
            error = "That's an empty fields"
            self.render_post(title, content, error)


def age_str(age):
    s = 'queried %s seconds ago'
    age = int(age)
    if age == 1:
        s = s.replace('seconds', 'second')
    return s % age


class FrontHandler(BlogHandler):
    def get(self):
        self.redirect('/blog')


app = webapp2.WSGIApplication([('/', FrontHandler), ('/blog', MainPage), ('/blog/newpost', Newpost),
                               ("/blog/([0-9]+)(?:.json)?", Perma), ("/blog/signup", SignupHandler),
                               ("/welcome", WelcomeHandler), ('/blog/.json', BlogFront),
                               ("/blog/logout", LogoutHandler), ("/blog/flush", Flush),
                               ("/blog/login", LoginHandler)], debug=True)
