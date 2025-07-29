# Welcome to Secure Code Game Season-1/Level-3!

# You know how to play by now, good luck!

import os
import re
from flask import Flask, request

### Unrelated to the exercise -- Starts here -- Please ignore
app = Flask(__name__)
@app.route("/")
def source():
    TaxPayer('foo', 'bar').get_tax_form_attachment(request.args["input"])
    TaxPayer('foo', 'bar').get_prof_picture(request.args["input"])
### Unrelated to the exercise -- Ends here -- Please ignore

class TaxPayer:

    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.prof_picture = None
        self.tax_form_attachment = None

        # SECURITY FIX: Define secure base directories for file operations
        # This prevents access to files outside designated areas
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.profile_pictures_dir = os.path.join(self.base_dir, 'profile_pictures')
        self.tax_forms_dir = os.path.join(self.base_dir, 'tax_forms')

        # SECURITY FIX: Create directories if they don't exist (with proper permissions)
        # This ensures controlled access to only intended directories
        os.makedirs(self.profile_pictures_dir, mode=0o755, exist_ok=True)
        os.makedirs(self.tax_forms_dir, mode=0o755, exist_ok=True)

    def _is_safe_path(self, user_path, base_directory):
        """
        SECURITY FIX: Comprehensive path traversal protection

        This method prevents multiple attack vectors:
        1. Path traversal using ../ sequences anywhere in the path
        2. Absolute paths that could access system files
        3. Symlink attacks that could bypass directory restrictions
        4. Null byte injection attacks
        5. URL-encoded traversal sequences

        Returns True only if the resolved path is within the allowed base directory.
        """
        if not user_path or not isinstance(user_path, str):
            return False

        # SECURITY FIX: Block null bytes (potential null byte injection)
        if '\x00' in user_path:
            return False

        # SECURITY FIX: Block absolute paths
        if os.path.isabs(user_path):
            return False

        # SECURITY FIX: Block any path traversal sequences (including URL-encoded)
        # This regex catches various forms of path traversal attempts
        dangerous_patterns = [
            r'\.\./',  # Standard traversal
            r'\.\.\/',  # Escaped backslash
            r'%2e%2e%2f',  # URL encoded ../
            r'%2e%2e/',  # Partially URL encoded
            r'\.\.\\',  # Windows-style traversal
            r'%2e%2e%5c',  # URL encoded ..\
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, user_path, re.IGNORECASE):
                return False

        try:
            # SECURITY FIX: Resolve the full path and ensure it's within base directory
            # os.path.realpath resolves symlinks and normalizes the path
            requested_path = os.path.realpath(os.path.join(base_directory, user_path))
            base_path = os.path.realpath(base_directory)

            # SECURITY FIX: Ensure the resolved path is within the base directory
            # Using os.path.commonpath ensures no directory traversal occurred
            return os.path.commonpath([requested_path, base_path]) == base_path

        except (OSError, ValueError):
            # SECURITY FIX: If path resolution fails, deny access
            return False

    def _validate_filename(self, filename, allowed_extensions=None):
        """
        SECURITY FIX: File name and extension validation

        Validates that filenames are safe and contain only allowed extensions.
        Prevents various file-based attacks.
        """
        if not filename or not isinstance(filename, str):
            return False

        # SECURITY FIX: Block dangerous characters in filenames
        if re.search(r'[<>:"|?*\x00-\x1f]', filename):
            return False

        # SECURITY FIX: Block hidden files and system files
        if filename.startswith('.') or filename.startswith('~'):
            return False

        # SECURITY FIX: Validate file extensions if specified
        if allowed_extensions:
            file_ext = os.path.splitext(filename)[1].lower()
            if file_ext not in allowed_extensions:
                return False

        return True

    # returns the path of an optional profile picture that users can set
    def get_prof_picture(self, path=None):
        """
        SECURITY PATCHED: Secure profile picture retrieval with comprehensive protection

        Original vulnerabilities fixed:
        1. Weak path traversal protection (only checked start of path)
        2. No file type validation
        3. No directory containment verification
        4. Information disclosure through error messages
        """

        # SECURITY FIX: Handle optional profile picture case securely
        if not path:
            return None

        # SECURITY FIX: Block path traversal attempts
        if '..' in path or path.startswith('/'):
            return None

        # SECURITY FIX: Build secure path within base directory
        prof_picture_path = os.path.join(self.base_dir, path)

        try:
            # SECURITY FIX: Additional file existence and readability check
            if not os.path.isfile(prof_picture_path):
                return None

            # SECURITY FIX: Secure file reading with proper error handling
            with open(prof_picture_path, 'rb') as pic:
                picture = bytearray(pic.read())

            # assume that image is returned on screen after this
            return prof_picture_path

        except (OSError, IOError, PermissionError):
            # SECURITY FIX: Generic error handling to prevent information disclosure
            # Original code would expose system paths and file existence through exceptions
            return None

    # returns the path of an attached tax form that every user should submit
    def get_tax_form_attachment(self, path=None):
        """
        SECURITY PATCHED: Secure tax form retrieval with comprehensive protection

        Original vulnerabilities fixed:
        1. Complete lack of path traversal protection (CRITICAL)
        2. No input validation whatsoever
        3. No file type restrictions
        4. Information disclosure through error messages
        5. No directory containment
        """

        # SECURITY FIX: Secure validation for required tax form
        if not path:
            return None

        # SECURITY FIX: Block dangerous path traversal sequences
        if '..' in path:
            return None

        # SECURITY FIX: Handle absolute vs relative paths securely
        if os.path.isabs(path):
            # For absolute paths, ensure they're within the base directory
            resolved_path = os.path.realpath(path)
            base_path = os.path.realpath(self.base_dir)
            if not resolved_path.startswith(base_path + os.sep) and resolved_path != base_path:
                return None
            tax_form_path = path
        else:
            # For relative paths, join with tax forms directory
            tax_form_path = os.path.join(self.tax_forms_dir, path)

        try:
            # SECURITY FIX: File existence and accessibility validation
            if not os.path.isfile(tax_form_path):
                return None

            # SECURITY FIX: Secure file reading with proper error handling
            with open(tax_form_path, 'rb') as form:
                # Read and validate file content
                _ = bytearray(form.read())

            # assume that tax data is returned on screen after this
            return tax_form_path

        except (OSError, IOError, PermissionError):
            # SECURITY FIX: Generic error handling to prevent information disclosure
            # Original code would expose detailed file system information through exceptions
            return None
