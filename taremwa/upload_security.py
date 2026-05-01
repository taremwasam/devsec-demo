import os
import secrets
from pathlib import Path

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.files.storage import FileSystemStorage
from django.utils.text import get_valid_filename


AVATAR_MAX_BYTES = 2 * 1024 * 1024
DOCUMENT_MAX_BYTES = 5 * 1024 * 1024

ALLOWED_AVATAR_EXTENSIONS = {".jpg", ".jpeg", ".png"}
ALLOWED_DOCUMENT_EXTENSIONS = {".pdf"}

ALLOWED_AVATAR_CONTENT_TYPES = {"image/jpeg", "image/png"}
ALLOWED_DOCUMENT_CONTENT_TYPES = {"application/pdf"}

JPEG_SIGNATURES = (b"\xff\xd8\xff",)
PNG_SIGNATURES = (b"\x89PNG\r\n\x1a\n",)
PDF_SIGNATURES = (b"%PDF-",)


class PrivateUploadStorage(FileSystemStorage):
    @property
    def base_location(self):
        return os.fspath(settings.PRIVATE_UPLOAD_ROOT)

    @property
    def location(self):
        return os.fspath(settings.PRIVATE_UPLOAD_ROOT)


private_upload_storage = PrivateUploadStorage()


def build_private_upload_path(prefix, filename):
    extension = Path(filename).suffix.lower()
    token = secrets.token_hex(16)
    safe_extension = get_valid_filename(extension) or ""
    return f"{prefix}/{token}{safe_extension}"


def avatar_upload_to(instance, filename):
    return build_private_upload_path("avatars", filename)


def document_upload_to(instance, filename):
    return build_private_upload_path("documents", filename)


def _get_extension(uploaded_file):
    return Path(uploaded_file.name).suffix.lower()


def _read_prefix(uploaded_file, size=16):
    current_position = uploaded_file.tell()
    uploaded_file.seek(0)
    prefix = uploaded_file.read(size)
    uploaded_file.seek(current_position)
    return prefix


def _validate_size(uploaded_file, max_bytes, label):
    if uploaded_file.size > max_bytes:
        raise ValidationError(f"{label} files must be {max_bytes // (1024 * 1024)} MB or smaller.")


def _validate_extension(uploaded_file, allowed_extensions, label):
    extension = _get_extension(uploaded_file)
    if extension not in allowed_extensions:
        allowed_display = ", ".join(sorted(allowed_extensions))
        raise ValidationError(f"{label} files must use one of: {allowed_display}.")


def _validate_content_type(uploaded_file, allowed_content_types, label):
    content_type = getattr(uploaded_file, "content_type", "") or ""
    if content_type and content_type not in allowed_content_types:
        raise ValidationError(f"{label} upload content type is not allowed.")


def _validate_signature(uploaded_file, allowed_signatures, label):
    prefix = _read_prefix(uploaded_file)
    if not any(prefix.startswith(signature) for signature in allowed_signatures):
        raise ValidationError(f"{label} file contents do not match the allowed file type.")


def validate_avatar_upload(uploaded_file):
    _validate_size(uploaded_file, AVATAR_MAX_BYTES, "Avatar")
    _validate_extension(uploaded_file, ALLOWED_AVATAR_EXTENSIONS, "Avatar")
    _validate_content_type(uploaded_file, ALLOWED_AVATAR_CONTENT_TYPES, "Avatar")
    _validate_signature(uploaded_file, JPEG_SIGNATURES + PNG_SIGNATURES, "Avatar")


def validate_document_upload(uploaded_file):
    _validate_size(uploaded_file, DOCUMENT_MAX_BYTES, "Document")
    _validate_extension(uploaded_file, ALLOWED_DOCUMENT_EXTENSIONS, "Document")
    _validate_content_type(uploaded_file, ALLOWED_DOCUMENT_CONTENT_TYPES, "Document")
    _validate_signature(uploaded_file, PDF_SIGNATURES, "Document")


def safe_download_name(uploaded_file, fallback_name):
    original_name = Path(uploaded_file.name).name
    cleaned_name = get_valid_filename(original_name)
    return cleaned_name or fallback_name
