# coding: utf-8

from flask import Flask
from flask_sqlalchemy import SQLAlchemy# coding: utf-8
from sqlalchemy import Column, DateTime, Integer, SmallInteger, String, Text
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base

app = Flask(__name__)

db = SQLAlchemy(app)
Base = declarative_base()
metadata = Base.metadata
engine = create_engine('mysql://root:securepass@localhost/FlaskUsers')
db_session = scoped_session(sessionmaker(autocommit=False,autoflush=False,bind=engine))


class Users(db.Model):
    __bind_key__ = 'users'
    __tablename__ = 'users'
    ID = db.Column(db.Integer, primary_key=True)
    u_name = db.Column(db.String(100))
    p_word = db.Column(db.String(100))
    pj_salt = db.Column(db.String(50))
#    u_role = db.Column(db.String(20))

    def __init__(self, ID, u_name, p_word, pj_salt, urole):
        self.ID = ID
        self.u_name = u_name
        self.p_word = p_word
        self.pj_salt = pj_salt
#        self.u_role = u_role


    def is_authenticated(self):
        return True


    def is_active(self):
        return True


    def is_anonymous(self):
        return False


    def get_id(self):
        return unicode(self.ID)


    def get_urole(self):
        return self.urole
