import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "hades-final-2-secret-key-change-in-production")
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(BASE_DIR, "hades_secure.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
    TRAINED_MODELS_FOLDER = os.path.join(BASE_DIR, "trained_models")
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024 * 1024  # 10 GB max upload
    ALLOWED_EXTENSIONS = {"csv"}
    HADES_ROOT_PASSWORD = "hades_root_secure_2026"
    DB_ENCRYPTION_KEY = os.environ.get("DB_ENCRYPTION_KEY", "Hades32ByteSuperSecretKey123456!")
