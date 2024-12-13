import os
from flask import Flask, flash, redirect, render_template, request, session
from werkzeug.security import check_password_hash, generate_password_hash
import psycopg2
from psycopg2.extras import DictCursor
from functools import wraps



# Configure application
app = Flask(__name__)
app.secret_key = 'dev'

# Database helper function
def get_db():
    conn = psycopg2.connect(
        dbname="digitalcloset",
        user="postgres",
        password="rqgbqfmq",  # Use the password you set during PostgreSQL installation
        host="localhost",
        port="5432"
    )
    conn.cursor_factory = DictCursor
    return conn

# Initialize database and create tables
with get_db() as conn:
    with conn.cursor() as cur:
        # Users table
        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                hash TEXT NOT NULL
            )
        ''')
        
        # Inventories table
        cur.execute('''
            CREATE TABLE IF NOT EXISTS inventories (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                name TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Items table
        cur.execute('''
            CREATE TABLE IF NOT EXISTS items (
                id SERIAL PRIMARY KEY,
                inventory_id INTEGER NOT NULL REFERENCES inventories(id),
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                color TEXT NOT NULL,
                image_url TEXT,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()

# End of database stuff

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function



# auth stuff

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # Get form inputs
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        
        # Validate inputs
        if not username:
            flash("Must provide username")
            return redirect("/register")
            
        if not password:
            flash("Must provide password")
            return redirect("/register")
            
        if not confirmation:
            flash("Must confirm password")
            return redirect("/register")
            
        if password != confirmation:
            flash("Passwords must match")
            return redirect("/register")
        
        # Check if username exists
        with get_db() as db:
            if db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone():
                flash("Username already exists")
                return redirect("/register")
            
            # Insert new user
            db.execute(
                "INSERT INTO users (username, hash) VALUES (?, ?)",
                (username, generate_password_hash(password))
            )
            db.commit()
        
        # Redirect to login
        return redirect("/login")
    
    # GET request - show registration form
    return render_template("auth/register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    # Forget any user_id
    session.clear()

    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            flash("Must provide username")
            return redirect("/login")

        # Ensure password was submitted
        elif not request.form.get("password"):
            flash("Must provide password")
            return redirect("/login")

        # Query database for username
        with get_db() as db:
            user = db.execute(
                "SELECT * FROM users WHERE username = ?", 
                (request.form.get("username"),)
            ).fetchone()

            # Ensure username exists and password is correct
            if user is None or not check_password_hash(user["hash"], request.form.get("password")):
                flash("Invalid username and/or password")
                return redirect("/login")

            # Remember which user has logged in
            session["user_id"] = user["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("auth/login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# end of auth



@app.route("/")
@login_required
def index():
    with get_db() as db:
        inventories = db.execute(
            "SELECT * FROM inventories WHERE user_id = ?", 
            (session["user_id"],)
        ).fetchall()
    return render_template("index.html", inventories=inventories)

@app.route("/create_inventory", methods=["POST"])
@login_required
def create_inventory():
    name = request.form.get("inventory_name")
    if not name:
        flash("Please provide an inventory name")
        return redirect("/")
        
    with get_db() as db:
        db.execute(
            "INSERT INTO inventories (user_id, name) VALUES (?, ?)",
            (session["user_id"], name)
        )
        db.commit()
    return redirect("/")

@app.route("/inventory/<int:inventory_id>")
@login_required
def view_inventory(inventory_id):
    type_filter = request.args.get('type')
    
    with get_db() as db:
        # Get all user's inventories for sidebar
        inventories = db.execute(
            "SELECT * FROM inventories WHERE user_id = ?",
            (session["user_id"],)
        ).fetchall()
        
        # Get current inventory details
        inventory = db.execute(
            "SELECT * FROM inventories WHERE id = ? AND user_id = ?",
            (inventory_id, session["user_id"])
        ).fetchone()
        
        # Get items with optional type filter
        if type_filter:
            items = db.execute(
                "SELECT * FROM items WHERE inventory_id = ? AND type = ?",
                (inventory_id, type_filter)
            ).fetchall()
        else:
            items = db.execute(
                "SELECT * FROM items WHERE inventory_id = ?",
                (inventory_id,)
            ).fetchall()
        
    return render_template("inventory/view.html", 
                         inventories=inventories, 
                         inventory=inventory, 
                         items=items, 
                         type_filter=type_filter)

# item handling

@app.route("/inventory/<int:inventory_id>/add_item", methods=["POST"])
@login_required
def add_item(inventory_id):
    # Get form data
    name = request.form.get("name")
    type = request.form.get("type")
    color = request.form.get("color")
    image_url = request.form.get("image_url")
    description = request.form.get("description")

    # Verify inventory belongs to user
    with get_db() as db:
        inventory = db.execute(
            "SELECT * FROM inventories WHERE id = ? AND user_id = ?",
            (inventory_id, session["user_id"])
        ).fetchone()
        
        if inventory is None:
            return redirect("/")
            
        # Add the item
        db.execute(
            "INSERT INTO items (inventory_id, name, type, color, image_url, description) VALUES (?, ?, ?, ?, ?, ?)",
            (inventory_id, name, type, color, image_url, description)
        )
        db.commit()

    return redirect(f"/inventory/{inventory_id}")

@app.route("/inventory/<int:inventory_id>/edit_item/<int:item_id>", methods=["POST"])
@login_required
def edit_item(inventory_id, item_id):
    name = request.form.get("name")
    type = request.form.get("type")
    color = request.form.get("color")
    image_url = request.form.get("image_url")
    description = request.form.get("description")
    
    with get_db() as db:
        db.execute(
            "UPDATE items SET name = ?, type = ?, color = ?, image_url = ?, description = ? WHERE id = ? AND inventory_id = ?",
            (name, type, color, image_url, description, item_id, inventory_id)
        )
        db.commit()
    
    return redirect(f"/inventory/{inventory_id}")

@app.route("/inventory/<int:inventory_id>/duplicate_item/<int:item_id>", methods=["POST"])
@login_required
def duplicate_item(inventory_id, item_id):
    with get_db() as db:
        # Get original item
        item = db.execute(
            "SELECT * FROM items WHERE id = ? AND inventory_id = ?",
            (item_id, inventory_id)
        ).fetchone()
        
        # Create duplicate
        db.execute(
            "INSERT INTO items (inventory_id, name, type, color, description) VALUES (?, ?, ?, ?, ?)",
            (inventory_id, item['name'], item['type'], item['color'], item['description'])
        )
        db.commit()
    
    return redirect(f"/inventory/{inventory_id}")

@app.route("/inventory/<int:inventory_id>/delete_item/<int:item_id>", methods=["POST"])
@login_required
def delete_item(inventory_id, item_id):
    with get_db() as db:
        db.execute("DELETE FROM items WHERE id = ? AND inventory_id = ?", (item_id, inventory_id))
        db.commit()
    
    return redirect(f"/inventory/{inventory_id}")