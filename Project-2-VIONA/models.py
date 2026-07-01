from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import UserMixin

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(
        db.String(50),
        unique=True,
        nullable=False
    )

    email = db.Column(
        db.String(120),
        unique=True,
        nullable=False
    )

    password_hash = db.Column(
        db.String(255),
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    last_seen = db.Column(
        db.DateTime,
        nullable=True,
        default=datetime.utcnow
    )

    # Relationships
    contacts = db.relationship(
        'Contact',
        foreign_keys='Contact.user_id',
        backref='owner_user',
        lazy=True,
        cascade="all, delete-orphan"
    )
    
    sent_messages = db.relationship(
        'Message',
        backref='sender_user',
        lazy=True,
        cascade="all, delete-orphan"
    )
    
    conversations = db.relationship(
        'Conversation',
        secondary='conversation_participants',
        back_populates='participants',
        lazy=True
    )


class Contact(db.Model):
    __tablename__ = "contacts"
    __table_args__ = (
        db.UniqueConstraint('user_id', 'contact_user_id', name='unique_user_contact'),
    )

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete="CASCADE"), nullable=False)
    contact_user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete="CASCADE"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationship to get details of the contact user
    contact_user = db.relationship('User', foreign_keys=[contact_user_id])

    # Backward compatibility properties for templates
    @property
    def name(self):
        return self.contact_user.username if self.contact_user else "Unknown"

    @property
    def username(self):
        return self.contact_user.username if self.contact_user else None

    @property
    def email(self):
        return self.contact_user.email if self.contact_user else None


class Conversation(db.Model):
    __tablename__ = "conversations"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=True) # Group name if applicable
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    messages = db.relationship(
        'Message',
        backref='conversation',
        lazy=True,
        cascade="all, delete-orphan"
    )
    
    participants = db.relationship(
        'User',
        secondary='conversation_participants',
        back_populates='conversations',
        lazy=True
    )

    def get_display_name(self, current_user_id):
        """
        Dynamically resolves the name of the conversation.
        For private messaging (2 participants), it returns the other user's username.
        For group messaging (or if not resolved), it falls back to the conversation name.
        """
        if len(self.participants) == 2:
            other_user = next((u for u in self.participants if u.id != current_user_id), None)
            if other_user:
                return other_user.username
        return self.name or "Secure Session"

    def get_unread_count(self, user_id):
        """
        Returns the number of unread messages in this conversation for a given user.
        """
        return db.session.scalar(
            db.select(db.func.count(Message.id))
            .filter(
                Message.conversation_id == self.id,
                Message.sender_id != user_id,
                Message.is_read == False
            )
        )


class ConversationParticipant(db.Model):
    __tablename__ = "conversation_participants"
    __table_args__ = (
        db.UniqueConstraint('conversation_id', 'user_id', name='unique_conversation_participant'),
    )

    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversations.id', ondelete="CASCADE"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete="CASCADE"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Message(db.Model):
    __tablename__ = "messages"

    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversations.id', ondelete="CASCADE"), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete="CASCADE"), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    is_read = db.Column(db.Boolean, default=False)
    read_at = db.Column(db.DateTime, nullable=True)
    is_delivered = db.Column(db.Boolean, default=False)
    delivered_at = db.Column(db.DateTime, nullable=True)
    message_type = db.Column(db.String(20), default='text', nullable=False)

    # Backward compatibility properties for templates
    @property
    def text(self):
        return self.content

    @text.setter
    def text(self, value):
        self.content = value

    @property
    def created_at(self):
        return self.timestamp

    @property
    def sender(self):
        return self.sender_user.username if self.sender_user else "System"