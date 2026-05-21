from app import create_app
from models.database import db, User
from werkzeug.security import generate_password_hash

app = create_app()
with app.app_context():
    user = User.query.filter_by(username="admin").first()
    if user:
        user.is_admin = True
        user.password_hash = generate_password_hash("admin123")
        db.session.commit()
        print("User 'admin' elevated to Admin and password reset to 'admin123'.")
    else:
        new_admin = User(username="admin", email="admin@hades.ai", password_hash=generate_password_hash("admin123"), is_admin=True)
        db.session.add(new_admin)
        db.session.commit()
        print("Created new 'admin' user with Admin privileges.")
