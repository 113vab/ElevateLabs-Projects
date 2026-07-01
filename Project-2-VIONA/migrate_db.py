from app import app
from models import db
from datetime import datetime

print("Starting database schema migration...")
with app.app_context():
    # Execute raw SQL ALTER statements to support zero-downtime additions of the new columns
    try:
        db.session.execute(db.text("ALTER TABLE users ADD COLUMN IF NOT EXISTS last_seen TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW();"))
        print("Ensured column 'last_seen' exists in table 'users'.")
    except Exception as e:
        print(f"Error checking/adding last_seen: {e}")

    try:
        db.session.execute(db.text("ALTER TABLE messages ADD COLUMN IF NOT EXISTS read_at TIMESTAMP WITHOUT TIME ZONE;"))
        print("Ensured column 'read_at' exists in table 'messages'.")
    except Exception as e:
        print(f"Error checking/adding read_at: {e}")

    try:
        db.session.execute(db.text("ALTER TABLE messages ADD COLUMN IF NOT EXISTS message_type VARCHAR(20) DEFAULT 'text' NOT NULL;"))
        print("Ensured column 'message_type' exists in table 'messages'.")
    except Exception as e:
        print(f"Error checking/adding message_type: {e}")

    try:
        db.session.execute(db.text("ALTER TABLE messages ADD COLUMN IF NOT EXISTS is_delivered BOOLEAN DEFAULT FALSE;"))
        print("Ensured column 'is_delivered' exists in table 'messages'.")
    except Exception as e:
        print(f"Error checking/adding is_delivered: {e}")

    try:
        db.session.execute(db.text("ALTER TABLE messages ADD COLUMN IF NOT EXISTS delivered_at TIMESTAMP WITHOUT TIME ZONE;"))
        print("Ensured column 'delivered_at' exists in table 'messages'.")
    except Exception as e:
        print(f"Error checking/adding delivered_at: {e}")

    db.session.commit()
    print("Database schema migration completed successfully!")
