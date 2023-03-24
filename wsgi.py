from application import create_app, db, models
from faker import Faker
from faker.providers import profile,misc


app = create_app()


@app.cli.command("create_db")
def create_db():
    db.create_all()

@app.cli.command("seed_db")
def seed_db():
    fake = Faker()
    fake.add_provider(profile)
    fake.add_provider(misc)
    for i in range(10):
        p = fake.profile(fields=None, sex=None)
        u = models.User(name=p['name'],job=p['job'],password=fake.password(length=10), email=p['mail'])
        db.session.add(u)
        db.session.commit()
    p = fake.profile(fields=None, sex=None)
    admin = models.User(name='admin',job=p['job'],password=fake.password(length=10), email=p['mail'], role="admin")
    db.session.add(admin)
    db.session.commit()
    

@app.cli.command("drop_db")
def drop_db():
    db.drop_all()

@app.cli.command("reset_app")
def reset_app():
    db.drop_all()
    db.create_all()
    fake = Faker()
    fake.add_provider(profile)
    fake.add_provider(misc)
    for i in range(10):
        p = fake.profile(fields=None, sex=None)
        u = models.User(name=p['name'],job=p['job'],password=fake.password(length=10), email=p['mail'])
        db.session.add(u)
        db.session.commit()
    p = fake.profile(fields=None, sex=None)
    admin = models.User(name='admin',job=p['job'],password=fake.password(length=10), email=p['mail'], role="admin")
    db.session.add(admin)
    db.session.commit()


if __name__ == "__main__":
    app.run(host='0.0.0.0')
