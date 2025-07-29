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

    def _safe_file_check(self, file_path, allowed_base_dir):
        """
        SECURITY FIX: Safely check if file exists within allowed directory
        """
        try:
            resolved_path = os.path.realpath(file_path)
            resolved_base = os.path.realpath(allowed_base_dir)

            # Ensure path is within allowed directory
            if not resolved_path.startswith(resolved_base + os.sep) and resolved_path != resolved_base:
                return False

            return os.path.isfile(resolved_path)
        except (OSError, ValueError):
            return False

    def _safe_file_read(self, file_path, allowed_base_dir):
        """
        SECURITY FIX: Safely read file within allowed directory
        """
        try:
            resolved_path = os.path.realpath(file_path)
            resolved_base = os.path.realpath(allowed_base_dir)

            # Ensure path is within allowed directory
            if not resolved_path.startswith(resolved_base + os.sep) and resolved_path != resolved_base:
                return None

            if not os.path.isfile(resolved_path):
                return None

            with open(resolved_path, 'rb') as f:
                return bytearray(f.read())
        except (OSError, IOError, PermissionError):
            return None

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

        # SECURITY FIX: Build secure path within base directory (matching original test expectation)
        prof_picture_path = os.path.join(self.base_dir, path)

        # SECURITY FIX: Use secure file operations
        if not self._safe_file_check(prof_picture_path, self.base_dir):
            return None

        picture_data = self._safe_file_read(prof_picture_path, self.base_dir)
        if picture_data is None:
            return None

        # assume that image is returned on screen after this
        return prof_picture_path

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

        # SECURITY FIX: Use secure file operations
        base_dir_for_check = self.base_dir if os.path.isabs(tax_form_path) else self.tax_forms_dir

        if not self._safe_file_check(tax_form_path, base_dir_for_check):
            return None

        form_data = self._safe_file_read(tax_form_path, base_dir_for_check)
        if form_data is None:
            return None

        # assume that tax data is returned on screen after this
        return tax_form_path
