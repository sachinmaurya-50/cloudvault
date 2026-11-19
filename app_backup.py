
import os
import uuid
from datetime import datetime

from flask import (
    Flask, render_template, request, session,
    redirect, url_for, send_from_directory
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import func

app = Flask(__name__)

app.secret_key = "cloudvault-secret-key"

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///cloudvault.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024

# 5 GB storage limit per user
MAX_STORAGE_BYTES = 5 * 1024 * 1024 * 1024

UPLOAD_FOLDER = os.path.join(app.instance_path, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {
    "pdf", "png", "jpg", "jpeg", "gif", "webp",
    "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "txt", "csv", "zip", "rar",
    "mp4", "mov", "mkv", "webm", "avi",
    "mp3", "wav", "ogg"
}

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)


class CloudFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    original_name = db.Column(db.String(255), nullable=False)
    stored_name = db.Column(db.String(255), unique=True, nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    content_type = db.Column(db.String(120))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        existing_user = User.query.filter_by(email=email).first()

        if existing_user:
            return "Email already registered. Please use another email."

        new_user = User(
            name=name,
            email=email,
            password=generate_password_hash(password)
        )

        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session["user_id"] = user.id
            session["user_name"] = user.name
            return redirect(url_for("dashboard"))

        return "Invalid email or password"

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]

    files = CloudFile.query.filter_by(
        user_id=user_id
    ).order_by(CloudFile.uploaded_at.desc()).all()

    total_files = len(files)

    total_storage = db.session.query(
        func.coalesce(func.sum(CloudFile.file_size), 0)
    ).filter(
        CloudFile.user_id == user_id
    ).scalar()

    search_query = request.args.get("q", "").strip()

    if search_query:
        files = CloudFile.query.filter(
            CloudFile.user_id == user_id,
            CloudFile.original_name.ilike(f"%{search_query}%")
        ).order_by(CloudFile.uploaded_at.desc()).all()

    return render_template(
        "dashboard.html",
        user_name=session["user_name"],
        files=files,
        total_files=total_files,
        total_storage=total_storage,
        search_query=search_query
    )


@app.route("/upload", methods=["POST"])
def upload_file():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if "file" not in request.files:
        return "No file selected", 400

    file = request.files["file"]

    if file.filename == "":
        return "Please select a file", 400

    if not allowed_file(file.filename):
        return "File type not supported", 400

    original_name = secure_filename(file.filename)

    if not original_name:
        return "Invalid filename", 400

    # Calculate selected file size before saving
    file.stream.seek(0, os.SEEK_END)
    file_size = file.stream.tell()
    file.stream.seek(0)

    if file_size == 0:
        return "Empty files are not allowed", 400

    # Calculate current user's storage usage
    used_storage = db.session.query(
        func.coalesce(func.sum(CloudFile.file_size), 0)
    ).filter(
        CloudFile.user_id == session["user_id"]
    ).scalar()

    # Check 5 GB quota
    if used_storage + file_size > MAX_STORAGE_BYTES:
        remaining = max(0, MAX_STORAGE_BYTES - used_storage)
        remaining_gb = remaining / (1024 ** 3)

        return (
            f"Storage limit exceeded! Your limit is 5 GB. "
            f"Available space: {remaining_gb:.2f} GB.",
            400
        )

    extension = original_name.rsplit(".", 1)[1].lower()
    stored_name = f"{uuid.uuid4().hex}.{extension}"
    file_path = os.path.join(UPLOAD_FOLDER, stored_name)

    file.save(file_path)

    new_file = CloudFile(
        user_id=session["user_id"],
        original_name=original_name,
        stored_name=stored_name,
        file_size=file_size,
        content_type=file.mimetype
    )

    try:
        db.session.add(new_file)
        db.session.commit()

    except Exception:
        db.session.rollback()

        if os.path.exists(file_path):
            os.remove(file_path)

        raise

    return redirect(url_for("dashboard"))


@app.route("/download/<int:file_id>")
def download_file(file_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    cloud_file = CloudFile.query.filter_by(
        id=file_id,
        user_id=session["user_id"]
    ).first_or_404()

    return send_from_directory(
        UPLOAD_FOLDER,
        cloud_file.stored_name,
        as_attachment=True,
        download_name=cloud_file.original_name
    )


@app.route("/delete/<int:file_id>", methods=["POST"])
def delete_file(file_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    cloud_file = CloudFile.query.filter_by(
        id=file_id,
        user_id=session["user_id"]
    ).first_or_404()

    file_path = os.path.join(UPLOAD_FOLDER, cloud_file.stored_name)

    if os.path.exists(file_path):
        os.remove(file_path)

    db.session.delete(cloud_file)
    db.session.commit()

    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def home():
    return render_template("index.html")


@app.errorhandler(413)
def file_too_large(error):
    return "File too large. Maximum upload size is 500 MB.", 413


with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(debug=True)
