"""This module creates classes to represent the database structure for the
itemscatalog databaseself.
"""

import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


class User(Base):
    __tablename__ = 'user'
    name = Column(String(80), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))
    id = Column(Integer, primary_key=True)

    @property
    def serialize(self):
        return {
                'name': self.name,
                'email': self.email,
                'picture': self.picture,
                'id': self.id,
        }


class Category(Base):
    __tablename__ = 'category'
    name = Column(String(100), nullable=False)
    user = relationship(User)
    user_id = Column(Integer, ForeignKey('user.id'))
    id = Column(Integer, primary_key=True)

    @property
    def serialize(self):
        return {
                'name': self.name,
                'user': self.user.name,
                'id': self.id,
        }


class Item(Base):
    __tablename__ = 'item'
    name = Column(String(100), nullable=False)
    id = Column(Integer, primary_key=True)
    description = Column(String(250))
    category_id = Column(Integer, ForeignKey('category.id'))
    category = relationship(Category)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        return {
                'name': self.name,
                'description': self.description,
                'id': self.id,
                'user': self.user.name,
        }


engine = create_engine('sqlite:///itemscatalog.db')
Base.metadata.create_all(engine)
