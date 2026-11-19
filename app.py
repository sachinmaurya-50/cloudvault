
import os
import uuid
from datetime import datetime
from urllib.parse import quote

import boto3
from dotenv import load_dotenv
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from flask import (
    Flask, render_template, request, session,
    redirect, url_for, send_from_directory,
    Response, stream_with_context
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import func

# Load credentials from .env
load_dotenv()

app = Flask(__name__)
app.secret_key = "cloudvault-secret-key"

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///cloudvault.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024

# 5 GB storage limit per user
MAX_STORAGE_BYTES = 5 * 1024 * 1024 * 1024

# Existing local files folder (kept for old files)
UPLOAD_FOLDER = os.path.join(app.instance_path, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {
    "pdf", "png", "jpg", "jpeg", "gif", "webp",
    "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "txt", "csv", "zip", "rar",
    "mp4", "mov", "mkv", "webm", "avi",
    "mp3", "wav", "ogg"
}

# Fil One S3 configuration
FIL_REGION = os.getenv("FIL_REGION")
FIL_BUCKET = os.getenv("FIL_BUCKET")
FIL_ACCESS_KEY = os.getenv("FIL_ACCESS_KEY")
FIL_SECRET_KEY = os.getenv("FIL_SECRET_KEY")

if not all([FIL_REGION, FIL_BUCKET, FIL_ACCESS_KEY, FIL_SECRET_KEY]):
    raise RuntimeError(
        "Fil One settings missing. Check your .env file."
    )

s3 = boto3.client(
    "s3",
    endpoint_url=f"https://s3.{FIL_REGION}.filonecontent.com",
    aws_access_key_id=FIL_ACCESS_KEY,
    aws_secret_access_key=FIL_SECRET_KEY,
    region_name=FIL_REGION,
    config=Config(s3={"addressing_style": "path"})
)

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

    # Calculate file size
    file.stream.seek(0, os.SEEK_END)
    file_size = file.stream.tell()
    file.stream.seek(0)

    if file_size == 0:
        return "Empty files are not allowed", 400

    # Check user's existing storage usage
    user_id = session["user_id"]

    used_storage = db.session.query(
        func.coalesce(func.sum(CloudFile.file_size), 0)
    ).filter(
        CloudFile.user_id == user_id
    ).scalar()

    if used_storage + file_size > MAX_STORAGE_BYTES:
        remaining = max(0, MAX_STORAGE_BYTES - used_storage)
        remaining_gb = remaining / (1024 ** 3)

        return (
            f"Storage limit exceeded! Your limit is 5 GB. "
            f"Available space: {remaining_gb:.2f} GB.",
            400
        )

    extension = original_name.rsplit(".", 1)[1].lower()

    # New files are stored in Fil One
    object_key = f"cloud/{uuid.uuid4().hex}.{extension}"

    try:
        file.stream.seek(0)

        s3.upload_fileobj(
            file.stream,
            FIL_BUCKET,
            object_key,
            ExtraArgs={
                "ContentType": file.mimetype or "application/octet-stream"
            }
        )

        new_file = CloudFile(
            user_id=user_id,
            original_name=original_name,
            stored_name=object_key,
            file_size=file_size,
            content_type=file.mimetype
        )

        db.session.add(new_file)
        db.session.commit()

    except Exception as error:
        db.session.rollback()

        try:
            s3.delete_object(Bucket=FIL_BUCKET, Key=object_key)
        except Exception:
            pass

        app.logger.exception("Cloud upload failed")
        return f"Cloud upload failed: {type(error).__name__}", 500

    return redirect(url_for("dashboard"))


@app.route("/view/<int:file_id>")
def view_file(file_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    cloud_file = CloudFile.query.filter_by(
        id=file_id,
        user_id=session["user_id"]
    ).first_or_404()

    # Only PDF and images can be previewed
    extension = cloud_file.original_name.rsplit(".", 1)[-1].lower()

    if extension != "pdf" and extension not in {
        "png", "jpg", "jpeg", "gif", "webp"
    }:
        return "Preview is not available for this file type.", 400

    if cloud_file.stored_name.startswith("cloud/"):
        try:
            result = s3.get_object(
                Bucket=FIL_BUCKET,
                Key=cloud_file.stored_name
            )

            body = result["Body"]

            def generate_file():
                try:
                    for chunk in body.iter_chunks(chunk_size=1024 * 1024):
                        if chunk:
                            yield chunk
                finally:
                    body.close()

            response = Response(
                stream_with_context(generate_file()),
                mimetype=cloud_file.content_type or "application/octet-stream"
            )

            response.headers["Content-Disposition"] = "inline"
            response.headers["X-Content-Type-Options"] = "nosniff"
            return response

        except (BotoCoreError, ClientError):
            app.logger.exception("Preview failed")
            return "Could not preview this cloud file.", 502

    # Old local files
    return send_from_directory(
        UPLOAD_FOLDER,
        cloud_file.stored_name,
        mimetype=cloud_file.content_type,
        as_attachment=False
    )


@app.route("/rename/<int:file_id>", methods=["POST"])
def rename_file(file_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    cloud_file = CloudFile.query.filter_by(
        id=file_id,
        user_id=session["user_id"]
    ).first_or_404()

    requested_name = request.form.get("new_name", "").strip()
    new_name = secure_filename(requested_name)

    if not new_name or "." not in new_name:
        return "Enter a valid filename including its extension.", 400

    old_extension = cloud_file.original_name.rsplit(".", 1)[-1].lower()
    new_extension = new_name.rsplit(".", 1)[-1].lower()

    if old_extension != new_extension:
        return "Changing the file extension is not allowed.", 400

    if new_name == cloud_file.original_name:
        return redirect(url_for("dashboard"))

    old_key = cloud_file.stored_name
    new_key = old_key
    cloud_copy_created = False
    local_old_path = None
    local_new_path = None

    try:
        if old_key.startswith("cloud/"):
            # Copy first; update database; delete old object only after commit.
            new_key = f"cloud/{uuid.uuid4().hex}.{new_extension}"

            s3.copy_object(
                Bucket=FIL_BUCKET,
                CopySource={"Bucket": FIL_BUCKET, "Key": old_key},
                Key=new_key
            )
            cloud_copy_created = True

            cloud_file.original_name = new_name
            cloud_file.stored_name = new_key
            db.session.commit()

            try:
                s3.delete_object(Bucket=FIL_BUCKET, Key=old_key)
            except Exception:
                app.logger.exception(
                    "Old cloud object cleanup failed after rename"
                )

        else:
            local_old_path = os.path.join(UPLOAD_FOLDER, old_key)
            new_key = f"{uuid.uuid4().hex}.{new_extension}"
            local_new_path = os.path.join(UPLOAD_FOLDER, new_key)

            os.rename(local_old_path, local_new_path)

            cloud_file.original_name = new_name
            cloud_file.stored_name = new_key
            db.session.commit()

    except Exception:
        db.session.rollback()

        if cloud_copy_created:
            try:
                s3.delete_object(Bucket=FIL_BUCKET, Key=new_key)
            except Exception:
                app.logger.exception("Could not clean up temporary cloud copy")

        if local_old_path and local_new_path and os.path.exists(local_new_path):
            try:
                os.rename(local_new_path, local_old_path)
            except OSError:
                app.logger.exception(
                    "Could not restore local file after rename failure"
                )

        app.logger.exception("Rename failed")
        return "Rename failed. Check the server terminal for details.", 500

    return redirect(url_for("dashboard"))


@app.route("/download/<int:file_id>")
def download_file(file_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    cloud_file = CloudFile.query.filter_by(
        id=file_id,
        user_id=session["user_id"]
    ).first_or_404()

    # New files are downloaded from Fil One
    if cloud_file.stored_name.startswith("cloud/"):
        try:
            result = s3.get_object(
                Bucket=FIL_BUCKET,
                Key=cloud_file.stored_name
            )

            body = result["Body"]

            def generate_file():
                try:
                    for chunk in body.iter_chunks(chunk_size=1024 * 1024):
                        if chunk:
                            yield chunk
                finally:
                    body.close()

            response = Response(
                stream_with_context(generate_file()),
                mimetype=cloud_file.content_type or "application/octet-stream"
            )

            safe_name = secure_filename(cloud_file.original_name) or "download"
            response.headers["Content-Disposition"] = (
                f"attachment; filename=\"{safe_name}\"; "
                f"filename*=UTF-8''{quote(cloud_file.original_name)}"
            )
            response.headers["Content-Length"] = str(cloud_file.file_size)

            return response

        except (BotoCoreError, ClientError):
            app.logger.exception("Cloud download failed")
            return "Cloud download failed. Please try again.", 502

    # Old files continue to download from local storage
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

    try:
        if cloud_file.stored_name.startswith("cloud/"):
            s3.delete_object(
                Bucket=FIL_BUCKET,
                Key=cloud_file.stored_name
            )
        else:
            file_path = os.path.join(UPLOAD_FOLDER, cloud_file.stored_name)

            if os.path.exists(file_path):
                os.remove(file_path)

        db.session.delete(cloud_file)
        db.session.commit()

    except Exception as error:
        db.session.rollback()
        app.logger.exception("File deletion failed")
        return f"File deletion failed: {type(error).__name__}", 500

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
