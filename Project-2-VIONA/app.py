from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO, emit, join_room, leave_room
from datetime import datetime

from config import Config
from models import db, User, Contact, Conversation, Message, ConversationParticipant
from forms import RegistrationForm, LoginForm

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)

bcrypt = Bcrypt(app)
socketio = SocketIO(app, cors_allowed_origins="*", manage_session=True)

# In-memory store for tracking online status
online_users = set()

# Configure Flask-Login LoginManager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message_category = "info"

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

with app.app_context():
    db.create_all()

@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    form = RegistrationForm()

    if form.validate_on_submit():
        # Check if email or username already exists
        existing_email = db.session.scalar(
            db.select(User).filter_by(email=form.email.data)
        )
        existing_user = db.session.scalar(
            db.select(User).filter_by(username=form.username.data)
        )
        
        if existing_email:
            flash("Email address is already registered.", "danger")
            return render_template("register.html", form=form)
        if existing_user:
            flash("Username is already taken.", "danger")
            return render_template("register.html", form=form)

        hashed_password = bcrypt.generate_password_hash(
            form.password.data
        ).decode("utf-8")

        user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=hashed_password
        )

        db.session.add(user)
        db.session.commit()

        flash("Account created successfully! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template(
        "register.html",
        form=form
    )

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    form = LoginForm()

    if form.validate_on_submit():
        user = db.session.scalar(
            db.select(User).filter_by(email=form.email.data)
        )

        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            flash(f"Welcome back, {user.username}!", "success")
            next_page = request.args.get("next")
            return redirect(next_page or url_for("dashboard"))
        else:
            flash("Invalid email or password. Please check your credentials.", "danger")

    return render_template(
        "login.html",
        form=form
    )

def seed_dev_data(user):
    mock_users_data = [
        {"username": "sarah_agent", "email": "sarah.j@viona.io"},
        {"username": "john_sec", "email": "john.v@viona.io"},
        {"username": "viona_bot", "email": "bot@viona.io"}
    ]
    
    seeded_users = {}
    for ud in mock_users_data:
        u = db.session.scalar(db.select(User).filter_by(username=ud["username"]))
        if not u:
            p_hash = bcrypt.generate_password_hash("secure_password_123").decode("utf-8")
            u = User(
                username=ud["username"],
                email=ud["email"],
                password_hash=p_hash
            )
            u.last_seen = datetime.utcnow()
            db.session.add(u)
            db.session.flush()
        seeded_users[ud["username"]] = u
        
    for username, target_user in seeded_users.items():
        c = db.session.scalar(db.select(Contact).filter_by(user_id=user.id, contact_user_id=target_user.id))
        if not c:
            contact = Contact(user_id=user.id, contact_user_id=target_user.id)
            db.session.add(contact)
            
    db.session.flush()
    for username, target_user in seeded_users.items():
        existing_conv = db.session.scalar(
            db.select(Conversation)
            .join(ConversationParticipant)
            .filter(ConversationParticipant.user_id.in_([user.id, target_user.id]))
            .group_by(Conversation.id)
            .having(db.func.count(ConversationParticipant.user_id) == 2)
        )
        if not existing_conv:
            conv = Conversation(name=target_user.username)
            db.session.add(conv)
            db.session.flush()
            
            part1 = ConversationParticipant(conversation_id=conv.id, user_id=user.id)
            part2 = ConversationParticipant(conversation_id=conv.id, user_id=target_user.id)
            db.session.add_all([part1, part2])
            db.session.flush()
            
            if username == "sarah_agent":
                m1 = Message(
                    conversation_id=conv.id,
                    sender_id=target_user.id,
                    content="Hey! Just verifying our secure channel setup. All communications are simplified and safe here.",
                    is_delivered=True,
                    delivered_at=datetime.utcnow()
                )
                m2 = Message(
                    conversation_id=conv.id,
                    sender_id=target_user.id,
                    content="Let's keep our notes in this secure workspace. Let me know if you need anything else.",
                    is_delivered=True,
                    delivered_at=datetime.utcnow()
                )
                db.session.add_all([m1, m2])
            elif username == "john_sec":
                m1 = Message(
                    conversation_id=conv.id,
                    sender_id=target_user.id,
                    content="System baseline checks complete. Connection is fully encrypted and private.",
                    is_delivered=True,
                    delivered_at=datetime.utcnow()
                )
                db.session.add(m1)
            elif username == "viona_bot":
                m1 = Message(
                    conversation_id=conv.id,
                    sender_id=target_user.id,
                    content="Welcome to VIONA! Your private keys have been generated locally. Happy secure messaging!",
                    is_delivered=True,
                    delivered_at=datetime.utcnow(),
                    is_read=True,
                    read_at=datetime.utcnow()
                )
                db.session.add(m1)
                
    db.session.commit()

@app.route("/dashboard")
@login_required
def dashboard():
    # Fetch user's contacts ordering by contact's username
    contacts_query = db.select(Contact).join(User, Contact.contact_user_id == User.id).filter(Contact.user_id == current_user.id)
    contacts = db.session.scalars(contacts_query.order_by(User.username)).all()
    
    # In development mode, if user has no contacts, seed sample content so the UI feels alive
    if not contacts:
        try:
            seed_dev_data(current_user)
            # Re-fetch contacts after seeding
            contacts = db.session.scalars(contacts_query.order_by(User.username)).all()
        except Exception as e:
            print(f"Error seeding development mock data: {e}")

    # Fetch user's conversations through ConversationParticipant
    conversations = db.session.scalars(
        db.select(Conversation)
        .join(ConversationParticipant)
        .filter(ConversationParticipant.user_id == current_user.id)
        .order_by(Conversation.updated_at.desc())
    ).all()

    for conv in conversations:
        conv.display_name = conv.get_display_name(current_user.id)
        conv.unread_count = conv.get_unread_count(current_user.id)

    # Verify database connection state
    db_connected = False
    try:
        db.session.execute(db.text("SELECT 1"))
        db_connected = True
    except Exception:
        pass

    return render_template(
        "dashboard.html",
        contacts=contacts,
        conversations=conversations,
        db_connected=db_connected
    )

@app.route("/api/contacts", methods=["POST"])
@login_required
def add_contact():
    data = request.get_json() or {}
    name = data.get("name")
    email = data.get("email")
    username = data.get("username")
    if not name:
        return {"error": "Name is required"}, 400
        
    # Check if a user with this name, email, or username exists in the User table
    search_term = username or name
    other_user = db.session.scalar(
        db.select(User).filter(
            db.or_(
                User.username == search_term,
                User.email == search_term,
                User.email == email
            )
        )
    )
    
    # If the user doesn't exist, create a placeholder registered User account
    # to maintain standard relational integrity constraints in contacts/conversations
    if not other_user:
        placeholder_username = username or name.lower().replace(" ", "_")
        placeholder_email = email or f"{placeholder_username}@example.com"
        
        # Verify placeholder isn't already registered
        other_user = db.session.scalar(
            db.select(User).filter(
                db.or_(
                    User.username == placeholder_username,
                    User.email == placeholder_email
                )
            )
        )
        if not other_user:
            placeholder_password = bcrypt.generate_password_hash("secure_password_123").decode("utf-8")
            other_user = User(
                username=placeholder_username,
                email=placeholder_email,
                password_hash=placeholder_password
            )
            db.session.add(other_user)
            db.session.flush() # Populate other_user.id
            
    # Check if this contact relationship already exists
    existing = db.session.scalar(
        db.select(Contact).filter_by(user_id=current_user.id, contact_user_id=other_user.id)
    )
    if existing:
        return {
            "id": existing.id,
            "name": existing.name,
            "email": existing.email,
            "username": existing.username
        }, 200
        
    contact = Contact(user_id=current_user.id, contact_user_id=other_user.id)
    db.session.add(contact)
    db.session.commit()
    
    return {
        "id": contact.id,
        "name": contact.name,
        "email": contact.email,
        "username": contact.username
    }, 201

@app.route("/api/contacts/<int:contact_id>", methods=["DELETE"])
@login_required
def delete_contact(contact_id):
    contact = db.session.get(Contact, contact_id)
    if not contact or contact.user_id != current_user.id:
        return {"error": "Contact not found"}, 404
    db.session.delete(contact)
    db.session.commit()
    return {"success": True}

@app.route("/api/users/search", methods=["GET"])
@login_required
def search_users():
    q = request.args.get("q", "").strip()
    if not q or len(q) < 2:
        return [], 200
        
    users = db.session.scalars(
        db.select(User)
        .filter(
            db.and_(
                User.id != current_user.id,
                db.or_(
                    User.username.ilike(f"%{q}%"),
                    User.email.ilike(f"%{q}%")
                )
            )
        )
        .limit(10)
    ).all()
    
    contact_user_ids = db.session.scalars(
        db.select(Contact.contact_user_id).filter_by(user_id=current_user.id)
    ).all()
    
    return [{
        "id": u.id,
        "username": u.username,
        "email": u.email,
        "is_contact": u.id in contact_user_ids
    } for u in users], 200

@app.route("/api/conversations", methods=["POST"])
@login_required
def start_conversation():
    data = request.get_json() or {}
    name = data.get("name")
    if not name:
        return {"error": "Name is required"}, 400
        
    # Check if other user exists
    other_user = db.session.scalar(
        db.select(User).filter(db.or_(User.username == name, User.email == name))
    )
    
    if other_user:
        # Check for existing private conversation containing both users
        existing_conv = db.session.scalar(
            db.select(Conversation)
            .join(ConversationParticipant)
            .filter(ConversationParticipant.user_id.in_([current_user.id, other_user.id]))
            .group_by(Conversation.id)
            .having(db.func.count(ConversationParticipant.user_id) == 2)
        )
        if existing_conv:
            return {
                "id": existing_conv.id,
                "name": other_user.username
            }, 200
            
        conv = Conversation(name=other_user.username)
        db.session.add(conv)
        db.session.flush()
        
        part1 = ConversationParticipant(conversation_id=conv.id, user_id=current_user.id)
        part2 = ConversationParticipant(conversation_id=conv.id, user_id=other_user.id)
        db.session.add_all([part1, part2])
        db.session.commit()
        
        return {
            "id": conv.id,
            "name": other_user.username
        }, 201
    else:
        # Fallback to single participant conversation or matching named conversation
        existing_conv = db.session.scalar(
            db.select(Conversation)
            .join(ConversationParticipant)
            .filter(ConversationParticipant.user_id == current_user.id, Conversation.name == name)
        )
        if existing_conv:
            return {
                "id": existing_conv.id,
                "name": existing_conv.name
            }, 200
            
        conv = Conversation(name=name)
        db.session.add(conv)
        db.session.flush()
        
        part = ConversationParticipant(conversation_id=conv.id, user_id=current_user.id)
        db.session.add(part)
        db.session.commit()
        
        return {
            "id": conv.id,
            "name": conv.name
        }, 201

@app.route("/api/conversations/<int:conv_id>/messages", methods=["GET", "POST"])
@login_required
def conversation_messages(conv_id):
    conv = db.session.get(Conversation, conv_id)
    if not conv:
        return {"error": "Conversation not found"}, 404
        
    # Verify the current user is a participant of the conversation
    is_part = db.session.scalar(
        db.select(ConversationParticipant).filter_by(conversation_id=conv_id, user_id=current_user.id)
    )
    if not is_part:
        return {"error": "Conversation not found or access denied"}, 403
    
    if request.method == "POST":
        data = request.get_json() or {}
        text = data.get("text")
        if not text:
            return {"error": "Message text is required"}, 400
        
        msg = Message(
            conversation_id=conv.id,
            sender_id=current_user.id,
            content=text,
            message_type=data.get("message_type", "text")
        )
        
        # Check if other user is online
        other_part = db.session.scalar(
            db.select(ConversationParticipant)
            .filter(ConversationParticipant.conversation_id == conv_id, ConversationParticipant.user_id != current_user.id)
        )
        if other_part:
            other_user = db.session.get(User, other_part.user_id)
            if other_user and other_user.username in online_users:
                msg.is_delivered = True
                msg.delivered_at = datetime.utcnow()
                
        db.session.add(msg)
        db.session.commit()
        
        return {
            "id": msg.id,
            "sender": "me",
            "text": msg.content,
            "is_read": msg.is_read,
            "read_at": msg.read_at.isoformat() if msg.read_at else None,
            "is_delivered": msg.is_delivered,
            "delivered_at": msg.delivered_at.isoformat() if msg.delivered_at else None,
            "message_type": msg.message_type,
            "created_at": msg.timestamp.isoformat()
        }, 201
    
    messages = db.session.scalars(
        db.select(Message).filter_by(conversation_id=conv.id).order_by(Message.timestamp.asc())
    ).all()
    
    # Mark messages from other users as read and delivered when conversation is loaded
    updated = False
    for m in messages:
        if m.sender_id != current_user.id:
            if not m.is_delivered:
                m.is_delivered = True
                m.delivered_at = datetime.utcnow()
                updated = True
            if not m.is_read:
                m.is_read = True
                m.read_at = datetime.utcnow()
                updated = True
    if updated:
        db.session.commit()
        # Emit real-time read receipts
        socketio.emit('messages_read', {
            'conversation_id': conv_id,
            'reader_id': current_user.id
        }, room=f"conversation_{conv_id}")
        
    return [{
        "id": m.id,
        "sender": "me" if m.sender_id == current_user.id else m.sender_user.username,
        "text": m.content,
        "is_read": m.is_read,
        "read_at": m.read_at.isoformat() if m.read_at else None,
        "is_delivered": m.is_delivered,
        "delivered_at": m.delivered_at.isoformat() if m.delivered_at else None,
        "message_type": m.message_type,
        "created_at": m.timestamp.isoformat()
    } for m in messages]

import random
@app.route("/api/conversations/<int:conv_id>/simulate-reply", methods=["POST"])
@login_required
def simulate_reply(conv_id):
    conv = db.session.get(Conversation, conv_id)
    if not conv:
        return {"error": "Conversation not found"}, 404
        
    # Verify user is participant
    is_part = db.session.scalar(
        db.select(ConversationParticipant).filter_by(conversation_id=conv_id, user_id=current_user.id)
    )
    if not is_part:
        return {"error": "Unauthorized"}, 403
        
    responses = [
        "This connection is fully encrypted and private.",
        "Hello! I am online and my identity is verified.",
        "Got your message. Let's keep our notes in this secure workspace.",
        "All communications are simplified and safe here.",
        "Understood. Let me know if you need anything else.",
        "Confirmed. Purging temporary logs on session close."
    ]
    
    reply_text = random.choice(responses)
    
    # In a private chat, the sender is the other participant
    other_part = db.session.scalar(
        db.select(ConversationParticipant)
        .filter(ConversationParticipant.conversation_id == conv_id, ConversationParticipant.user_id != current_user.id)
    )
    sender_id = other_part.user_id if other_part else current_user.id
    
    msg = Message(
        conversation_id=conv.id,
        sender_id=sender_id,
        content=reply_text
    )
    db.session.add(msg)
    db.session.commit()
    
    return {
        "id": msg.id,
        "sender": msg.sender_user.username if msg.sender_id != current_user.id else "me",
        "text": msg.content,
        "created_at": msg.timestamp.isoformat()
    }, 201


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been successfully logged out.", "info")
    return redirect(url_for("login"))


# ==========================================================================
# SOCKET.IO REAL-TIME EVENT HANDLERS
# ==========================================================================

@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        online_users.add(current_user.username)
        current_user.last_seen = datetime.utcnow()
        
        # Mark all messages sent to current_user that are not delivered as delivered
        conv_ids = db.session.scalars(
            db.select(ConversationParticipant.conversation_id).filter_by(user_id=current_user.id)
        ).all()
        if conv_ids:
            undelivered_msgs = db.session.scalars(
                db.select(Message)
                .filter(
                    Message.conversation_id.in_(conv_ids),
                    Message.sender_id != current_user.id,
                    Message.is_delivered == False
                )
            ).all()
            if undelivered_msgs:
                for m in undelivered_msgs:
                    m.is_delivered = True
                    m.delivered_at = datetime.utcnow()
                db.session.commit()
                # Broadcast messages_delivered to relevant conversation rooms
                for c_id in set(m.conversation_id for m in undelivered_msgs):
                    socketio.emit('messages_delivered', {
                        'conversation_id': c_id,
                        'receiver_id': current_user.id
                    }, room=f"conversation_{c_id}")
            else:
                db.session.commit()
        else:
            db.session.commit()

        # Broadcast online status
        emit('user_status_change', {
            'username': current_user.username,
            'status': 'online'
        }, broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        if current_user.username in online_users:
            online_users.remove(current_user.username)
        current_user.last_seen = datetime.utcnow()
        db.session.commit()
        # Broadcast offline status with last_seen time
        emit('user_status_change', {
            'username': current_user.username,
            'status': 'offline',
            'last_seen': current_user.last_seen.isoformat()
        }, broadcast=True)

@socketio.on('get_online_users')
def handle_get_online_users():
    if current_user.is_authenticated:
        emit('online_users_list', list(online_users))

@socketio.on('join_conversation')
def handle_join_conversation(data):
    if not current_user.is_authenticated:
        return False
    conv_id = data.get('conversation_id')
    if not conv_id:
        return False
        
    # Verify participant membership
    is_part = db.session.scalar(
        db.select(ConversationParticipant).filter_by(conversation_id=conv_id, user_id=current_user.id)
    )
    if is_part:
        room_name = f"conversation_{conv_id}"
        join_room(room_name)
        return True
    return False

@socketio.on('leave_conversation')
def handle_leave_conversation(data):
    if not current_user.is_authenticated:
        return False
    conv_id = data.get('conversation_id')
    if conv_id:
        room_name = f"conversation_{conv_id}"
        leave_room(room_name)
        return True
    return False

@socketio.on('mark_read')
def handle_mark_read(data):
    if not current_user.is_authenticated:
        return
    conv_id = data.get('conversation_id')
    message_id = data.get('message_id')
    if not conv_id:
        return
        
    if message_id:
        msg = db.session.get(Message, message_id)
        if msg and msg.conversation_id == conv_id and msg.sender_id != current_user.id:
            updated = False
            if not msg.is_delivered:
                msg.is_delivered = True
                msg.delivered_at = datetime.utcnow()
                updated = True
            if not msg.is_read:
                msg.is_read = True
                msg.read_at = datetime.utcnow()
                updated = True
            if updated:
                db.session.commit()
                emit('messages_read', {
                    'conversation_id': conv_id,
                    'message_id': message_id,
                    'reader_id': current_user.id
                }, room=f"conversation_{conv_id}")
    else:
        # Mark all unread messages in conversation as read
        unread_msgs = db.session.scalars(
            db.select(Message)
            .filter(Message.conversation_id == conv_id, Message.sender_id != current_user.id, Message.is_read == False)
        ).all()
        if unread_msgs:
            for m in unread_msgs:
                m.is_delivered = True
                if not m.delivered_at:
                    m.delivered_at = datetime.utcnow()
                m.is_read = True
                m.read_at = datetime.utcnow()
            db.session.commit()
            emit('messages_read', {
                'conversation_id': conv_id,
                'reader_id': current_user.id
            }, room=f"conversation_{conv_id}")

@socketio.on('send_message')
def handle_send_message(data):
    if not current_user.is_authenticated:
        return False
    conv_id = data.get('conversation_id')
    text = data.get('text', '').strip()
    msg_type = data.get('message_type', 'text')
    if not conv_id or not text:
        return False
        
    # Verify participant membership
    is_part = db.session.scalar(
        db.select(ConversationParticipant).filter_by(conversation_id=conv_id, user_id=current_user.id)
    )
    if not is_part:
        return False
        
    # Save User message to database
    msg = Message(
        conversation_id=conv_id,
        sender_id=current_user.id,
        content=text,
        message_type=msg_type
    )
    
    # Check if other participant is online to mark delivered immediately
    other_part = db.session.scalar(
        db.select(ConversationParticipant)
        .filter(ConversationParticipant.conversation_id == conv_id, ConversationParticipant.user_id != current_user.id)
    )
    if other_part:
        other_user = db.session.get(User, other_part.user_id)
        if other_user and other_user.username in online_users:
            msg.is_delivered = True
            msg.delivered_at = datetime.utcnow()

    db.session.add(msg)
    
    # Touch conversation timestamp
    conv = db.session.get(Conversation, conv_id)
    if conv:
        conv.updated_at = datetime.utcnow()
    db.session.commit()
    
    # Broadcast message to room
    payload = {
        'id': msg.id,
        'conversation_id': conv_id,
        'sender_id': current_user.id,
        'sender_name': current_user.username,
        'text': msg.content,
        'is_read': msg.is_read,
        'read_at': msg.read_at.isoformat() if msg.read_at else None,
        'is_delivered': msg.is_delivered,
        'delivered_at': msg.delivered_at.isoformat() if msg.delivered_at else None,
        'message_type': msg.message_type,
        'timestamp': msg.timestamp.isoformat()
    }
    emit('new_message', payload, room=f"conversation_{conv_id}")
    
    # Trigger auto-reply simulation for contacts
    if other_part:
        other_user = db.session.get(User, other_part.user_id)
        other_username = other_user.username if other_user else "Contact"
        
        def send_simulated_reply(c_id, target_sender_id, target_sender_name):
            import time
            time.sleep(0.3)
            # Emit typing indicator start
            socketio.emit('user_typing', {
                'conversation_id': c_id,
                'user_id': target_sender_id,
                'username': target_sender_name,
                'is_typing': True
            }, room=f"conversation_{c_id}")
            
            time.sleep(0.9)
            
            with app.app_context():
                responses = [
                    "This connection is fully encrypted and private.",
                    "Hello! I am online and my identity is verified.",
                    "Got your message. Let's keep our notes in this secure workspace.",
                    "All communications are simplified and safe here.",
                    "Understood. Let me know if you need anything else.",
                    "Confirmed. Purging temporary logs on session close."
                ]
                reply_text = random.choice(responses)
                
                # Save message (delivered since sender is online)
                reply_msg = Message(
                    conversation_id=c_id,
                    sender_id=target_sender_id,
                    content=reply_text,
                    message_type='text',
                    is_delivered=True,
                    delivered_at=datetime.utcnow()
                )
                db.session.add(reply_msg)
                
                conv_to_update = db.session.get(Conversation, c_id)
                if conv_to_update:
                    conv_to_update.updated_at = datetime.utcnow()
                db.session.commit()
                
                # Emit typing indicator end
                socketio.emit('user_typing', {
                    'conversation_id': c_id,
                    'user_id': target_sender_id,
                    'username': target_sender_name,
                    'is_typing': False
                }, room=f"conversation_{c_id}")
                
                # Emit to room
                socketio.emit('new_message', {
                    'id': reply_msg.id,
                    'conversation_id': c_id,
                    'sender_id': target_sender_id,
                    'sender_name': target_sender_name,
                    'text': reply_msg.content,
                    'is_read': reply_msg.is_read,
                    'read_at': reply_msg.read_at.isoformat() if reply_msg.read_at else None,
                    'is_delivered': reply_msg.is_delivered,
                    'delivered_at': reply_msg.delivered_at.isoformat() if reply_msg.delivered_at else None,
                    'message_type': reply_msg.message_type,
                    'timestamp': reply_msg.timestamp.isoformat()
                }, room=f"conversation_{c_id}")
                
        socketio.start_background_task(
            send_simulated_reply,
            conv_id,
            other_part.user_id,
            other_username
        )

@socketio.on('typing')
def handle_typing(data):
    if not current_user.is_authenticated:
        return False
    conv_id = data.get('conversation_id')
    is_typing = data.get('is_typing', False)
    if conv_id:
        emit('user_typing', {
            'conversation_id': conv_id,
            'user_id': current_user.id,
            'username': current_user.username,
            'is_typing': is_typing
        }, room=f"conversation_{conv_id}", include_self=False)


if __name__ == "__main__":
    socketio.run(app, debug=True)