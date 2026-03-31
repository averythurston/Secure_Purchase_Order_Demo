from app import app
from models import db, User
from werkzeug.security import generate_password_hash

with app.app_context():
    db.drop_all()
    db.create_all()

    users = [
        User(
            username="purchaser1",
            password_hash=generate_password_hash("pass123"),
            role="purchaser"
        ),
        User(
            username="supervisor1",
            password_hash=generate_password_hash("pass123"),
            role="supervisor"
        ),
        User(
            username="purchasing1",
            password_hash=generate_password_hash("pass123"),
            role="purchasing"
        )
    ]

    db.session.add_all(users)
    db.session.commit()

    print("Database initialized with sample users.")