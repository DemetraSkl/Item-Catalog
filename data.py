from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Category, Item
import datetime


""" Populate database(DB) with template data """

engine = create_engine('sqlite:///categoriesappwithusers.db')
# Bind engine to metadata of the Base to access
# declaratives through DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# DBSession instance functions as a staging zone
# prior to loading objects into a DB
session = DBSession()

# Creator user
User1 = User(
    name="Pikos Apikos",
    email="pikos@fruitopology.net",
    picture='http://www.stickpng.com/\
    assets/thumbs/580b57fcd9996e24bc43c187.png')
session.add(User1)
session.commit()

# Items for Breads
category1 = Category(user_id=1, name="Breads")

session.add(category1)
session.commit()

item1 = Item(
    user_id=1,
    name="Sourdough",
    description="Sourdough recipe ...",
    category=category1)

session.add(item1)
session.commit()

item2 = Item(
    user_id=1,
    name="Baguette",
    description="Baguette recipe ...",
    category=category1)

session.add(item2)
session.commit()

# Items for Apetizers
category2 = Category(user_id=1, name="Soups")

session.add(category2)
session.commit()

item1 = Item(
    user_id=1,
    name="Lintels",
    description="Lintel recipe ...",
    category=category2)

session.add(item1)
session.commit()


# Items for Salads
category3 = Category(user_id=1, name="Salads")

session.add(category3)
session.commit()

# Items for Breakfast
category4 = Category(user_id=1, name="Breakfasts")

session.add(category4)
session.commit()

# Items for Main Dishes
category5 = Category(user_id=1, name="Main Courses")

session.add(category5)
session.commit()

# Items for Desserts
category6 = Category(user_id=1, name="Desserts")

session.add(category6)
session.commit()

print "added items!"
