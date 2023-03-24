from flask_script import Manager
from application import create_app, db, models
from faker import Faker
from faker.providers import profile,misc

app = create_app()
manager = Manager(app)

fake = Faker()
fake.add_provider(profile)
fake.add_provider(misc)

@manager.command
def create_db():
    db.create_all()

@manager.command
def seed_db():
    for i in range(10):
        p = fake.profile(fields=None, sex=None)
        u = models.User(name=p['name'],job=p['job'],password=fake.password(length=10), email=p['mail'])
        db.session.add(u)
        db.session.commit()
    p = fake.profile(fields=None, sex=None)
    admin = models.User(name='admin',job=p['job'],password=fake.password(length=10), email=p['mail'], role="admin")
    db.session.add(admin)
    db.session.commit()
    

@manager.command
def drop_db():
    db.drop_all()

@manager.command
def reset_app():
    db.drop_all()
    db.create_all()
    seed_db()

if __name__ == "__main__":
    manager.run()