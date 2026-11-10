import os, sqlite3, secrets, re, json
from datetime import datetime
from flask import Flask, request, jsonify, g, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

DB_PATH = "marketplace.db"
UPLOAD_FOLDER = "uploads"
ALLOWED_EXT = {"png","jpg","jpeg","gif","webp"}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app = Flask(__name__)

@app.after_request
def cors(resp):
    resp.headers["Access-Control-Allow-Origin"]="*"
    resp.headers["Access-Control-Allow-Headers"]="Content-Type, Authorization"
    resp.headers["Access-Control-Allow-Methods"]="GET, POST, PUT, DELETE, OPTIONS"
    return resp
@app.route("/api/<path:_any>", methods=["OPTIONS"])
def preflight(_any): return ("",204)

def get_db():
    if "db" not in g:
        g.db=sqlite3.connect(DB_PATH); g.db.row_factory=sqlite3.Row
    return g.db
@app.teardown_appcontext
def close_db(_exc):
    db=g.pop("db",None)
    if db: db.close()

def init_db():
    db=sqlite3.connect(DB_PATH)
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS tokens(token TEXT PRIMARY KEY,user_id INTEGER NOT NULL,created_at TEXT NOT NULL,FOREIGN KEY(user_id) REFERENCES users(id));
    CREATE TABLE IF NOT EXISTS items(id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT NOT NULL,description TEXT NOT NULL,price REAL NOT NULL,category TEXT NOT NULL DEFAULT 'General',image_url TEXT,seller_id INTEGER NOT NULL,created_at TEXT NOT NULL,FOREIGN KEY(seller_id) REFERENCES users(id));
    CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY AUTOINCREMENT,item_id INTEGER NOT NULL,sender_name TEXT NOT NULL,sender_email TEXT NOT NULL,message TEXT NOT NULL,created_at TEXT NOT NULL,FOREIGN KEY(item_id) REFERENCES items(id));
    CREATE TABLE IF NOT EXISTS likes(id INTEGER PRIMARY KEY AUTOINCREMENT,item_id INTEGER NOT NULL,user_id INTEGER NOT NULL,created_at TEXT NOT NULL,UNIQUE(item_id,user_id));
    CREATE TABLE IF NOT EXISTS saves(id INTEGER PRIMARY KEY AUTOINCREMENT,item_id INTEGER NOT NULL,user_id INTEGER NOT NULL,created_at TEXT NOT NULL,UNIQUE(item_id,user_id));
    CREATE TABLE IF NOT EXISTS comments(id INTEGER PRIMARY KEY AUTOINCREMENT,item_id INTEGER NOT NULL,user_id INTEGER,user_name TEXT,text TEXT NOT NULL,created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS password_resets(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,code TEXT NOT NULL,created_at TEXT NOT NULL,used INTEGER NOT NULL DEFAULT 0,FOREIGN KEY(user_id) REFERENCES users(id));
    CREATE TABLE IF NOT EXISTS agent_applications(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,phone TEXT NOT NULL,email TEXT NOT NULL,area TEXT NOT NULL,message TEXT,created_at TEXT NOT NULL);
    """)
    # lightweight migrations for DBs created before these columns existed
    user_cols={r[1] for r in db.execute("PRAGMA table_info(users)").fetchall()}
    if "avatar_url" not in user_cols: db.execute("ALTER TABLE users ADD COLUMN avatar_url TEXT")
    if "contact" not in user_cols: db.execute("ALTER TABLE users ADD COLUMN contact TEXT")
    item_cols={r[1] for r in db.execute("PRAGMA table_info(items)").fetchall()}
    if "location" not in item_cols: db.execute("ALTER TABLE items ADD COLUMN location TEXT")
    if "contact" not in item_cols: db.execute("ALTER TABLE items ADD COLUMN contact TEXT")
    if "images" not in item_cols: db.execute("ALTER TABLE items ADD COLUMN images TEXT")
    db.commit(); db.close()

EMAIL_RE=re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
def error(m,s=400): return jsonify({"error":m}),s
def current_user():
    a=request.headers.get("Authorization","")
    if not a.startswith("Bearer "): return None
    t=a[7:].strip(); db=get_db()
    return db.execute("SELECT users.* FROM tokens JOIN users ON users.id=tokens.user_id WHERE tokens.token=?",(t,)).fetchone()
def require_auth():
    u=current_user()
    if not u: return None, error("Not logged in",401)
    return u,None

def save_uploaded_file(f):
    """Save an uploaded werkzeug FileStorage, return its public URL or None if invalid/missing."""
    if not f or f.filename=="": return None
    ext=f.filename.rsplit(".",1)[-1].lower() if "." in f.filename else ""
    if ext not in ALLOWED_EXT: return None
    fn=secure_filename(secrets.token_hex(12)+"."+ext)
    f.save(os.path.join(UPLOAD_FOLDER,fn))
    return f"/uploads/{fn}"

def user_public(r):
    cols=r.keys()
    return {
        "id":r["id"],"name":r["name"],"email":r["email"],
        "avatar_url":r["avatar_url"] if "avatar_url" in cols else None,
        "contact":r["contact"] if "contact" in cols else None,
    }

def parse_images(r):
    """Return the list of image URLs for an item row, from the new `images` JSON column,
    falling back to the legacy single `image_url` column."""
    cols=r.keys()
    raw=r["images"] if "images" in cols else None
    if raw:
        try:
            lst=json.loads(raw)
            if isinstance(lst,list) and lst:
                return [u for u in lst if isinstance(u,str) and u]
        except (ValueError, TypeError):
            pass
    img=r["image_url"] if "image_url" in cols else None
    return [img] if img else []

def _extract_images(data):
    """Pull a list of image URLs out of a create/update item payload: accepts either
    `image_urls` (list, or JSON-encoded list) or the legacy single `image_url`."""
    raw=data.get("image_urls")
    if raw:
        try:
            lst=raw if isinstance(raw,list) else json.loads(raw)
            lst=[u.strip() for u in lst if isinstance(u,str) and u.strip()]
            if lst: return lst
        except (ValueError, TypeError):
            pass
    single=(data.get("image_url") or "").strip()
    return [single] if single else []

def item_public(r, db=None):
    cols=r.keys()
    images=parse_images(r)
    d={
        "id":r["id"],"title":r["title"],"description":r["description"],"price":r["price"],
        "category":r["category"],"image_url":images[0] if images else None,"images":images,
        "location":r["location"] if "location" in cols else None,
        "contact":r["contact"] if "contact" in cols else None,
        "seller_id":r["seller_id"],"created_at":r["created_at"]
    }
    if db is not None:
        d["likes_count"]=db.execute("SELECT COUNT(*) c FROM likes WHERE item_id=?",(r["id"],)).fetchone()["c"]
        d["comments_count"]=db.execute("SELECT COUNT(*) c FROM comments WHERE item_id=?",(r["id"],)).fetchone()["c"]
    return d

def enrich(item, db, user):
    if user:
        item["liked"]=bool(db.execute("SELECT 1 FROM likes WHERE item_id=? AND user_id=?",(item["id"],user["id"])).fetchone())
        item["saved"]=bool(db.execute("SELECT 1 FROM saves WHERE item_id=? AND user_id=?",(item["id"],user["id"])).fetchone())
    else:
        item["liked"]=False; item["saved"]=False
    return item

@app.route("/api/signup", methods=["POST"])
def signup():
    if request.content_type and "multipart/form-data" in request.content_type:
        data=request.form; avatar_file=request.files.get("avatar")
    else:
        data=request.get_json(silent=True) or {}; avatar_file=None
    name=(data.get("name") or "").strip(); email=(data.get("email") or "").strip().lower(); pw=data.get("password") or ""
    contact=(data.get("contact") or "").strip() or None
    if not name or not email or not pw: return error("Name, email and password required.")
    if not EMAIL_RE.match(email): return error("Invalid email.")
    if len(pw)<6: return error("Password must be at least 6 characters.")
    db=get_db()
    if db.execute("SELECT id FROM users WHERE email=?",(email,)).fetchone(): return error("Email already exists.",409)
    avatar_url=None
    if avatar_file and avatar_file.filename:
        avatar_url=save_uploaded_file(avatar_file)
        if avatar_url is None: return error("Avatar must be png, jpg, jpeg, gif or webp.")
    now=datetime.utcnow().isoformat()
    cur=db.execute("INSERT INTO users(name,email,password_hash,avatar_url,contact,created_at) VALUES(?,?,?,?,?,?)",(name,email,generate_password_hash(pw),avatar_url,contact,now))
    uid=cur.lastrowid; token=secrets.token_hex(24)
    db.execute("INSERT INTO tokens(token,user_id,created_at) VALUES(?,?,?)",(token,uid,now)); db.commit()
    return jsonify({"token":token,"user":user_public(db.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone())})

@app.route("/api/login", methods=["POST"])
def login():
    data=request.get_json(silent=True) or {}
    email=(data.get("email") or "").strip().lower(); pw=data.get("password") or ""
    db=get_db(); u=db.execute("SELECT * FROM users WHERE email=?",(email,)).fetchone()
    if not u or not check_password_hash(u["password_hash"],pw): return error("Incorrect email or password.",401)
    token=secrets.token_hex(24); db.execute("INSERT INTO tokens(token,user_id,created_at) VALUES(?,?,?)",(token,u["id"],datetime.utcnow().isoformat())); db.commit()
    return jsonify({"token":token,"user":user_public(u)})

@app.route("/api/forgot-password", methods=["POST"])
def forgot_password():
    data=request.get_json(silent=True) or {}
    email=(data.get("email") or "").strip().lower()
    if not email or not EMAIL_RE.match(email): return error("Enter a valid email.")
    db=get_db(); user=db.execute("SELECT * FROM users WHERE email=?",(email,)).fetchone()
    if not user: return error("No account found with that email.",404)
    code="".join(secrets.choice("0123456789") for _ in range(6))
    db.execute("INSERT INTO password_resets(user_id,code,created_at,used) VALUES(?,?,?,0)",(user["id"],code,datetime.utcnow().isoformat())); db.commit()
    return jsonify({"ok":True,"reset_code":code})

@app.route("/api/reset-password", methods=["POST"])
def reset_password():
    data=request.get_json(silent=True) or {}
    email=(data.get("email") or "").strip().lower(); code=(data.get("code") or "").strip(); new_pw=data.get("new_password") or ""
    if not email or not code or not new_pw: return error("Email, code and new password required.")
    if len(new_pw)<6: return error("Password must be at least 6 characters.")
    db=get_db(); user=db.execute("SELECT * FROM users WHERE email=?",(email,)).fetchone()
    if not user: return error("Invalid request.")
    row=db.execute("SELECT * FROM password_resets WHERE user_id=? AND code=? AND used=0 ORDER BY created_at DESC LIMIT 1",(user["id"],code)).fetchone()
    if not row: return error("Invalid or expired reset code.")
    db.execute("UPDATE users SET password_hash=? WHERE id=?",(generate_password_hash(new_pw),user["id"]))
    db.execute("UPDATE password_resets SET used=1 WHERE id=?",(row["id"],))
    db.execute("DELETE FROM tokens WHERE user_id=?",(user["id"],))
    db.commit()
    return jsonify({"ok":True})

@app.route("/api/account", methods=["PUT"])
def update_account():
    user,err=require_auth()
    if err: return err
    db=get_db()
    if request.content_type and "multipart/form-data" in request.content_type:
        data=request.form; f=request.files.get("avatar")
    else:
        data=request.get_json(silent=True) or {}; f=None
    name=(data.get("name") or user["name"]).strip()
    email=(data.get("email") or user["email"]).strip().lower()
    if not name or not email: return error("Name and email required.")
    if not EMAIL_RE.match(email): return error("Invalid email.")
    if email!=user["email"] and db.execute("SELECT id FROM users WHERE email=? AND id!=?",(email,user["id"])).fetchone():
        return error("Email already in use.",409)
    avatar_url=user["avatar_url"]
    if f and f.filename:
        new_url=save_uploaded_file(f)
        if new_url is None: return error("Avatar must be png, jpg, jpeg, gif or webp.")
        avatar_url=new_url
    db.execute("UPDATE users SET name=?,email=?,avatar_url=? WHERE id=?",(name,email,avatar_url,user["id"])); db.commit()
    row=db.execute("SELECT * FROM users WHERE id=?",(user["id"],)).fetchone()
    return jsonify({"user":user_public(row)})

@app.route("/api/me", methods=["GET"])
def me():
    user,err=require_auth()
    if err: return err
    db=get_db()
    items=db.execute("SELECT * FROM items WHERE seller_id=? ORDER BY created_at DESC",(user["id"],)).fetchall()
    items_out=[]
    total=0
    for r in items:
        d=item_public(r,db); total+=d["likes_count"]; items_out.append(d)
    saved_rows=db.execute("SELECT items.* FROM saves JOIN items ON items.id=saves.item_id WHERE saves.user_id=? ORDER BY saves.created_at DESC",(user["id"],)).fetchall()
    saved=[item_public(r,db) for r in saved_rows]
    msgs=db.execute("SELECT messages.*, items.title as item_title FROM messages JOIN items ON items.id=messages.item_id WHERE items.seller_id=? ORDER BY messages.created_at DESC",(user["id"],)).fetchall()
    msgs_out=[{"id":m["id"],"item_id":m["item_id"],"sender_name":m["sender_name"],"sender_email":m["sender_email"],"message":m["message"],"created_at":m["created_at"]} for m in msgs]
    return jsonify({"user":user_public(user),"items":items_out,"saved":saved,"messages":msgs_out,"total_likes":total,"items_count":len(items_out)})

@app.route("/api/me", methods=["DELETE"])
def delete_me():
    user,err=require_auth()
    if err: return err
    db=get_db()
    item_ids=[r["id"] for r in db.execute("SELECT id FROM items WHERE seller_id=?",(user["id"],)).fetchall()]
    for iid in item_ids:
        db.execute("DELETE FROM messages WHERE item_id=?",(iid,))
        db.execute("DELETE FROM likes WHERE item_id=?",(iid,))
        db.execute("DELETE FROM saves WHERE item_id=?",(iid,))
        db.execute("DELETE FROM comments WHERE item_id=?",(iid,))
    db.execute("DELETE FROM items WHERE seller_id=?",(user["id"],))
    db.execute("DELETE FROM likes WHERE user_id=?",(user["id"],))
    db.execute("DELETE FROM saves WHERE user_id=?",(user["id"],))
    db.execute("DELETE FROM tokens WHERE user_id=?",(user["id"],))
    db.execute("DELETE FROM users WHERE id=?",(user["id"],))
    db.commit()
    return jsonify({"ok":True})

@app.route("/api/items", methods=["GET"])
def list_items():
    search=(request.args.get("search") or "").strip(); cat=(request.args.get("category") or "").strip()
    q="SELECT items.*, users.name as seller_name, users.avatar_url as seller_avatar FROM items JOIN users ON users.id=items.seller_id WHERE 1=1"; params=[]
    if search: q+=" AND (title LIKE ? OR description LIKE ?)"; params+=[f"%{search}%",f"%{search}%"]
    if cat and cat.lower()!="all": q+=" AND category=?"; params.append(cat)
    q+=" ORDER BY created_at DESC"
    db=get_db(); rows=db.execute(q,params).fetchall(); user=current_user(); out=[]
    for r in rows:
        d=item_public(r,db); d["seller"]={"id":r["seller_id"],"name":r["seller_name"],"avatar_url":r["seller_avatar"]}; out.append(enrich(d,db,user))
    return jsonify(out)

@app.route("/api/items/<int:item_id>", methods=["GET"])
def get_item(item_id):
    db=get_db(); row=db.execute("SELECT * FROM items WHERE id=?",(item_id,)).fetchone()
    if not row: return error("Item not found.",404)
    seller=db.execute("SELECT * FROM users WHERE id=?",(row["seller_id"],)).fetchone()
    d=item_public(row,db); d["seller"]=user_public(seller) if seller else None
    return jsonify(enrich(d,db,current_user()))

@app.route("/api/items", methods=["POST"])
def create_item():
    user,err=require_auth()
    if err: return err
    data=request.get_json(silent=True) or {}
    title=(data.get("title") or "").strip(); desc=(data.get("description") or "").strip(); price=data.get("price"); cat=(data.get("category") or "General").strip() or "General"
    location=(data.get("location") or "").strip() or None
    contact=(data.get("contact") or "").strip() or None
    images=_extract_images(data)
    if not title or not desc: return error("Title and description required.")
    try: price=float(price); assert price>=0
    except: return error("Price must be positive.")
    db=get_db(); now=datetime.utcnow().isoformat()
    first_img=images[0] if images else None
    cur=db.execute("INSERT INTO items(title,description,price,category,image_url,images,location,contact,seller_id,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (title,desc,price,cat,first_img,json.dumps(images) if images else None,location,contact,user["id"],now))
    db.commit()
    row=db.execute("SELECT * FROM items WHERE id=?",(cur.lastrowid,)).fetchone(); d=item_public(row,db); d["seller"]=user_public(user)
    return jsonify(d),201

@app.route("/api/items/<int:item_id>", methods=["PUT"])
def update_item(item_id):
    user,err=require_auth()
    if err: return err
    db=get_db(); row=db.execute("SELECT * FROM items WHERE id=?",(item_id,)).fetchone()
    if not row: return error("Item not found.",404)
    if row["seller_id"]!=user["id"]: return error("You can only edit your own items.",403)
    data=request.get_json(silent=True) or {}
    title=(data.get("title") or row["title"]).strip()
    desc=(data.get("description") or row["description"]).strip()
    price=data.get("price", row["price"])
    cat=(data.get("category") or row["category"]).strip() or row["category"]
    location=data.get("location"); location=location.strip() if isinstance(location,str) else (row["location"] if "location" in row.keys() else None)
    contact=data.get("contact"); contact=contact.strip() if isinstance(contact,str) else (row["contact"] if "contact" in row.keys() else None)
    if not title or not desc: return error("Title and description required.")
    try: price=float(price); assert price>=0
    except: return error("Price must be positive.")
    db.execute("UPDATE items SET title=?,description=?,price=?,category=?,location=?,contact=? WHERE id=?",
        (title,desc,price,cat,location or None,contact or None,item_id))
    db.commit()
    row2=db.execute("SELECT * FROM items WHERE id=?",(item_id,)).fetchone()
    d=item_public(row2,db); seller=db.execute("SELECT * FROM users WHERE id=?",(user["id"],)).fetchone(); d["seller"]=user_public(seller)
    return jsonify(d)

@app.route("/api/items/<int:item_id>", methods=["DELETE"])
def delete_item(item_id):
    user,err=require_auth()
    if err: return err
    db=get_db(); row=db.execute("SELECT * FROM items WHERE id=?",(item_id,)).fetchone()
    if not row: return error("Item not found.",404)
    if row["seller_id"]!=user["id"]: return error("You can only delete your own items.",403)
    db.execute("DELETE FROM items WHERE id=?",(item_id,)); db.execute("DELETE FROM messages WHERE item_id=?",(item_id,)); db.execute("DELETE FROM likes WHERE item_id=?",(item_id,)); db.execute("DELETE FROM saves WHERE item_id=?",(item_id,)); db.execute("DELETE FROM comments WHERE item_id=?",(item_id,)); db.commit()
    return jsonify({"ok":True})

@app.route("/api/items/<int:item_id>/contact", methods=["POST"])
def contact(item_id):
    db=get_db()
    if not db.execute("SELECT * FROM items WHERE id=?",(item_id,)).fetchone(): return error("Item not found.",404)
    data=request.get_json(silent=True) or {}; name=(data.get("name") or "").strip(); email=(data.get("email") or "").strip(); msg=(data.get("message") or "").strip()
    if not name or not email or not msg: return error("Name, email and message required.")
    if not EMAIL_RE.match(email): return error("Invalid email.")
    db.execute("INSERT INTO messages(item_id,sender_name,sender_email,message,created_at) VALUES(?,?,?,?,?)",(item_id,name,email,msg,datetime.utcnow().isoformat())); db.commit()
    return jsonify({"ok":True})

@app.route("/api/items/<int:item_id>/messages", methods=["GET"])
def item_msgs(item_id):
    user,err=require_auth()
    if err: return err
    db=get_db(); row=db.execute("SELECT * FROM items WHERE id=?",(item_id,)).fetchone()
    if not row: return error("Item not found.",404)
    if row["seller_id"]!=user["id"]: return error("Only seller can view.",403)
    rows=db.execute("SELECT * FROM messages WHERE item_id=? ORDER BY created_at DESC",(item_id,)).fetchall()
    return jsonify([{"id":r["id"],"sender_name":r["sender_name"],"sender_email":r["sender_email"],"message":r["message"],"created_at":r["created_at"]} for r in rows])

# LIKES / SAVES / COMMENTS
@app.route("/api/items/<int:item_id>/like", methods=["POST"])
def like_item(item_id):
    user,err=require_auth()
    if err: return err
    db=get_db()
    if not db.execute("SELECT * FROM items WHERE id=?",(item_id,)).fetchone(): return error("Item not found.",404)
    ex=db.execute("SELECT id FROM likes WHERE item_id=? AND user_id=?",(item_id,user["id"])).fetchone()
    if ex: db.execute("DELETE FROM likes WHERE id=?",(ex["id"],)); liked=False
    else: db.execute("INSERT INTO likes(item_id,user_id,created_at) VALUES(?,?,?)",(item_id,user["id"],datetime.utcnow().isoformat())); liked=True
    db.commit()
    count=db.execute("SELECT COUNT(*) c FROM likes WHERE item_id=?",(item_id,)).fetchone()["c"]
    return jsonify({"liked":liked,"likes_count":count})

@app.route("/api/items/<int:item_id>/save", methods=["POST"])
def save_item(item_id):
    user,err=require_auth()
    if err: return err
    db=get_db()
    if not db.execute("SELECT * FROM items WHERE id=?",(item_id,)).fetchone(): return error("Item not found.",404)
    ex=db.execute("SELECT id FROM saves WHERE item_id=? AND user_id=?",(item_id,user["id"])).fetchone()
    if ex: db.execute("DELETE FROM saves WHERE id=?",(ex["id"],)); saved=False
    else: db.execute("INSERT INTO saves(item_id,user_id,created_at) VALUES(?,?,?)",(item_id,user["id"],datetime.utcnow().isoformat())); saved=True
    db.commit(); return jsonify({"saved":saved})

@app.route("/api/items/<int:item_id>/comments", methods=["GET"])
def get_comments(item_id):
    db=get_db()
    rows=db.execute("SELECT comments.*, users.name as user_name FROM comments LEFT JOIN users ON users.id=comments.user_id WHERE item_id=? ORDER BY created_at ASC",(item_id,)).fetchall()
    return jsonify([{"id":r["id"],"user_name":r["user_name"] or "User","text":r["text"],"created_at":r["created_at"]} for r in rows])

@app.route("/api/items/<int:item_id>/comments", methods=["POST"])
def post_comment(item_id):
    user,err=require_auth()
    if err: return err
    db=get_db()
    if not db.execute("SELECT * FROM items WHERE id=?",(item_id,)).fetchone(): return error("Item not found.",404)
    data=request.get_json(silent=True) or {}; text=(data.get("text") or "").strip()
    if not text: return error("Comment cannot be empty.")
    db.execute("INSERT INTO comments(item_id,user_id,user_name,text,created_at) VALUES(?,?,?,?,?)",(item_id,user["id"],user["name"],text,datetime.utcnow().isoformat())); db.commit()
    return jsonify({"ok":True}),201

@app.route("/api/agent-apply", methods=["POST"])
def agent_apply():
    data=request.get_json(silent=True) or {}
    name=(data.get("name") or "").strip(); phone=(data.get("phone") or "").strip()
    email=(data.get("email") or "").strip(); area=(data.get("area") or "").strip(); message=(data.get("message") or "").strip()
    if not name or not phone or not email or not area: return error("Name, phone, email and area are required.")
    if not EMAIL_RE.match(email): return error("Invalid email.")
    db=get_db()
    db.execute("INSERT INTO agent_applications(name,phone,email,area,message,created_at) VALUES(?,?,?,?,?,?)",(name,phone,email,area,message,datetime.utcnow().isoformat())); db.commit()
    return jsonify({"ok":True}),201

@app.route("/api/upload", methods=["POST"])
def upload():
    user,err=require_auth()
    if err: return err
    f=request.files.get("image")
    if not f or f.filename=="": return error("No image file.")
    url=save_uploaded_file(f)
    if url is None: return error("Only png, jpg, jpeg, gif, webp.")
    return jsonify({"url":url})

@app.route("/uploads/<filename>")
def serve_upload(filename): return send_from_directory(UPLOAD_FOLDER,filename)

@app.route("/api/ads", methods=["GET"])
def ads():
    return jsonify([
        {"tag":"Sponsored","title":"20% Off This Week","subtitle":"Shop from top sellers in Arua","image":"https://picsum.photos/id/10/800/400","button_text":"Shop Now","action":"market"},
        {"tag":"New Sellers","title":"Post Your First Item Free","subtitle":"No fees. No stress.","image":"https://picsum.photos/id/20/800/400","button_text":"Post Item","action":"post"},
        {"tag":"Reward","title":"Invite a Friend, Get a Reward","subtitle":"Share YourMarket","image":"https://picsum.photos/id/30/800/400","button_text":"Invite Now","action":"signup"},
    ])

@app.route("/api/health", methods=["GET"])
def health(): return jsonify({"ok":True})

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
 
