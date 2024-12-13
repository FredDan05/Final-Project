import os
from flask import Flask, flash, redirect, render_template, request, session, jsonify
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
import psycopg2
from psycopg2.extras import DictCursor
from functools import wraps
from bs4 import BeautifulSoup
import requests
from googleapiclient.discovery import build


# Configure application
app = Flask(__name__)
app.secret_key = 'dev'
app.config['UPLOAD_FOLDER'] = 'static/uploads'

GOOGLE_API_KEY = os.getenv('AIzaSyB_GqXxJIOY35FpcRSkg1YRMihZtYb1QIo')
SEARCH_ENGINE_ID = os.getenv('0612f18a96e7a4b78')

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Database helper function
def get_db():
    DATABASE_URL = os.environ.get('DATABASE_URL',     client_encoding='UTF8')
    conn = psycopg2.connect(DATABASE_URL)
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
                subtype TEXT,
                size TEXT,
                color TEXT NOT NULL,
                image_url TEXT,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        
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
        
        with get_db() as db:
            with db.cursor() as cur:
                cur.execute("SELECT * FROM users WHERE username = %s", (username,))
                if cur.fetchone():
                    flash("Username already exists")
                    return redirect("/register")
                
                cur.execute(
                    "INSERT INTO users (username, hash) VALUES (%s, %s)",
                    (username, generate_password_hash(password))
                )
                db.commit()
        
        return redirect("/login")
    
    return render_template("auth/register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()

    if request.method == "POST":
        if not request.form.get("username"):
            flash("Must provide username")
            return redirect("/login")

        elif not request.form.get("password"):
            flash("Must provide password")
            return redirect("/login")

        with get_db() as db:
            with db.cursor() as cur:
                cur.execute(
                    "SELECT * FROM users WHERE username = %s", 
                    (request.form.get("username"),)
                )
                user = cur.fetchone()

                if user is None or not check_password_hash(user["hash"], request.form.get("password")):
                    flash("Invalid username and/or password")
                    return redirect("/login")

                session["user_id"] = user["id"]

        return redirect("/")

    return render_template("auth/login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/")
@login_required
def index():
    with get_db() as db:
        with db.cursor() as cur:
            cur.execute(
                "SELECT * FROM inventories WHERE user_id = %s", 
                (session["user_id"],)
            )
            inventories = cur.fetchall()
    return render_template("index.html", inventories=inventories)

@app.route("/create_inventory", methods=["POST"])
@login_required
def create_inventory():
    name = request.form.get("inventory_name")
    if not name:
        flash("Please provide an inventory name")
        return redirect("/")
        
    with get_db() as db:
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO inventories (user_id, name) VALUES (%s, %s)",
                (session["user_id"], name)
            )
            db.commit()
    return redirect("/")

@app.route("/inventory/<int:inventory_id>")
@login_required
def view_inventory(inventory_id):
    type_filter = request.args.get('type')
    
    with get_db() as db:
        with db.cursor() as cur:
            cur.execute(
                "SELECT * FROM inventories WHERE user_id = %s",
                (session["user_id"],)
            )
            inventories = cur.fetchall()
            
            cur.execute(
                "SELECT * FROM inventories WHERE id = %s AND user_id = %s",
                (inventory_id, session["user_id"])
            )
            inventory = cur.fetchone()
            
            if type_filter:
                cur.execute(
                    "SELECT * FROM items WHERE inventory_id = %s AND type = %s",
                    (inventory_id, type_filter)
                )
            else:
                cur.execute(
                    "SELECT * FROM items WHERE inventory_id = %s",
                    (inventory_id,)
                )
            items = cur.fetchall()
        
    return render_template("inventory/view.html", 
                         inventories=inventories, 
                         inventory=inventory, 
                         items=items, 
                         type_filter=type_filter)

@app.route("/inventory/<int:inventory_id>/add_item", methods=["POST"])
@login_required
def add_item(inventory_id):
    name = request.form.get("name")
    type = request.form.get("type")
    subtype = request.form.get("subtype")
    size = request.form.get("size")
    color = request.form.get("color")
    description = request.form.get("description")
    image_url = None
    
    if 'image' in request.files:
        file = request.files['image']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            image_url = f'/static/uploads/{filename}'
    elif request.form.get('image_url'):
        image_url = request.form.get('image_url')

    with get_db() as db:
        with db.cursor() as cur:
            cur.execute(
                "SELECT * FROM inventories WHERE id = %s AND user_id = %s",
                (inventory_id, session["user_id"])
            )
            inventory = cur.fetchone()
            
            if inventory is None:
                return redirect("/")
                
            cur.execute(
                "INSERT INTO items (inventory_id, name, type, subtype, size, color, image_url, description) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                (inventory_id, name, type, subtype, size, color, image_url, description)
            )
            db.commit()

    return redirect(f"/inventory/{inventory_id}")

@app.route("/inventory/<int:inventory_id>/edit_item/<int:item_id>", methods=["POST"])
@login_required
def edit_item(inventory_id, item_id):
    name = request.form.get("name")
    type = request.form.get("type")
    subtype = request.form.get("subtype")
    size = request.form.get("size")
    color = request.form.get("color")
    image_url = request.form.get("image_url")
    description = request.form.get("description")
    
    with get_db() as db:
        with db.cursor() as cur:
            cur.execute(
                "UPDATE items SET name = %s, type = %s, subtype = %s, size = %s, color = %s, image_url = %s, description = %s WHERE id = %s AND inventory_id = %s",
                (name, type, subtype, size, color, image_url, description, item_id, inventory_id)
            )
            db.commit()
    
    return redirect(f"/inventory/{inventory_id}")

@app.route("/inventory/<int:inventory_id>/duplicate_item/<int:item_id>", methods=["POST"])
@login_required
def duplicate_item(inventory_id, item_id):
    with get_db() as db:
        with db.cursor() as cur:
            cur.execute(
                "SELECT * FROM items WHERE id = %s AND inventory_id = %s",
                (item_id, inventory_id)
            )
            item = cur.fetchone()
            
            cur.execute(
                "INSERT INTO items (inventory_id, name, type, subtype, size, color, image_url, description) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                (inventory_id, item['name'], item['type'], item['subtype'], item['size'], item['color'], item['image_url'], item['description'])
            )
            db.commit()
    
    return redirect(f"/inventory/{inventory_id}")

@app.route("/inventory/<int:inventory_id>/delete_item/<int:item_id>", methods=["POST"])
@login_required
def delete_item(inventory_id, item_id):
    with get_db() as db:
        with db.cursor() as cur:
            cur.execute(
                "DELETE FROM items WHERE id = %s AND inventory_id = %s", 
                (item_id, inventory_id)
            )
            db.commit()
    
    return redirect(f"/inventory/{inventory_id}")


@app.route("/search_product_images", methods=["POST"])
@login_required
def search_product_images():
    data = request.get_json()
    product_name = data.get("product_name")
    website_url = data.get("website_url")
    
    try:
        images = []
        if website_url:
            # Handle direct URL
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(website_url, headers=headers)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find product images (common patterns in e-commerce sites)
            img_elements = soup.find_all('img', {
                'class': lambda x: x and any(term in x.lower() 
                    for term in ['product', 'main', 'gallery', 'primary'])
            })
            
            for img in img_elements:
                src = img.get('src') or img.get('data-src')
                if src:
                    if not src.startswith(('http://', 'https://')):
                        src = requests.compat.urljoin(website_url, src)
                    if any(ext in src.lower() for ext in ['.jpg', '.jpeg', '.png', '.webp']):
                        images.append(src)
        
        if product_name:
            # Use Google Custom Search API
            service = build("customsearch", "v1", developerKey=GOOGLE_API_KEY)
            result = service.cse().list(
                q=f"{product_name} product image",
                cx=SEARCH_ENGINE_ID,
                searchType='image',
                num=8,
                imgType='product',
                safe='active'
            ).execute()
            
            api_images = [item['link'] for item in result.get('items', [])]
            images.extend(api_images)
        
        return jsonify({
            'success': True,
            'images': list(set(images[:12]))  # Remove duplicates and limit to 12 images
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400


if __name__ == "__main__":
    app.run(debug=True)

