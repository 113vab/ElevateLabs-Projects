from app import app
from models import db

print("Resetting database...")
with app.app_context():
    db.drop_all()
    print("Dropped all existing tables.")
    db.create_all()
    print("Created all tables with new messaging foundation schema.")
print("Database reset completed successfully!")
