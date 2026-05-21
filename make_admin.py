
from app import create_app
from models.database import db, User

def make_admin():
    app = create_app()
    with app.app_context():
        users = User.query.all()
        for u in users:
            u.is_admin = True
            print(f"User {u.username} is now admin.")
        db.session.commit()

if __name__ == "__main__":
    make_admin()
