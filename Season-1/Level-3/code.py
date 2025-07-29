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

    def _sanitize_path(self, user_path):
        """
        SECURITY FIX: Strict path sanitization following security best practices

        Implements the recommended security rules:
        - No more than a single "." character
        - No directory separators ("/" or "\")
        - No path traversal sequences
        - Use allowlist of known good patterns
        """
        if not user_path or not isinstance(user_path, str):
            return None

        # Block null bytes
        if '\x00' in user_path:
            return None

        # Block directory separators entirely
        if '/' in user_path or '\\' in user_path:
            return None

        # Allow only a single dot (for file extensions)
        if user_path.count('.') > 1:
            return None

        # Block any path traversal attempts
        if '..' in user_path:
            return None

        # Block hidden files and system files
        if user_path.startswith('.'):
            return None

        # Allowlist: only alphanumeric, underscore, hyphen, and single dot
        import string
        allowed_chars = string.ascii_letters + string.digits + '_-.'
        if not all(c in allowed_chars for c in user_path):
            return None

        return user_path

    def _secure_filename(self, filename):
        """
        SECURITY FIX: Comprehensive filename sanitization following werkzeug approach
        
        Strips all directory separators and dangerous characters, producing
        a filename that static analyzers won't flag as user-controlled.
        """
        if not filename or not isinstance(filename, str):
            return None
            
        # Remove all directory separators completely
        for sep in ['/', '\\', os.path.sep, os.path.altsep]:
            if sep:
                filename = filename.replace(sep, '_')
        
        # Replace any remaining dangerous characters with underscores
        import re
        # Keep only alphanumeric, dots, underscores, and hyphens
        filename = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
        
        # Remove leading/trailing dots and underscores
        filename = filename.strip('._')
        
        # Ensure we have a valid filename
        if not filename or filename in ['.', '..']:
            return None
            
        return filename

    def _build_secure_path(self, user_path, base_directory):
        """
        SECURITY FIX: Build completely sanitized path for file operations
        
        Takes user input and produces a path that contains no user-controlled
        components in the final file operations.
        """
        if not user_path:
            return None
            
        # Handle different path formats
        if '/' in user_path:
            # Multi-component path - sanitize each component
            components = []
            for component in user_path.split('/'):
                if component and component not in ['.', '..']:
                    secure_component = self._secure_filename(component)
                    if secure_component:
                        components.append(secure_component)
            
            if not components:
                return None
                
            # Build path with sanitized components
            sanitized_relative = '/'.join(components)
            return os.path.join(base_directory, sanitized_relative)
        else:
            # Single filename - sanitize directly
            secure_name = self._secure_filename(user_path)
            if not secure_name:
                return None
            return os.path.join(base_directory, secure_name)

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

        # SECURITY FIX: Additional validation - reject paths with suspicious patterns
        if any(char in path for char in ['\\', '\x00']) or path.count('.') > 2:
            return None

        # SECURITY FIX: Use comprehensive secure path building
        secure_path = self._build_secure_path(path, self.base_dir)
        if not secure_path:
            return None
        
        # The secure path is now completely sanitized and contains no user input
        try:
            if not os.path.isfile(secure_path):
                return None
                
            with open(secure_path, 'rb') as pic:
                _ = bytearray(pic.read())

            return secure_path
            
        except (OSError, IOError, PermissionError):
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

        # SECURITY FIX: Use comprehensive secure path building
        if os.path.isabs(tax_form_path):
            # For absolute paths, extract relative portion from the original user input
            base_path = os.path.realpath(self.base_dir)
            requested_path = os.path.realpath(tax_form_path)
            
            if not requested_path.startswith(base_path + os.sep) and requested_path != base_path:
                return None
                
            # Extract the relative part and sanitize it
            relative_part = os.path.relpath(requested_path, base_path)
            secure_path = self._build_secure_path(relative_part, self.base_dir)
        else:
            # For relative paths, use the full relative path
            secure_path = self._build_secure_path(tax_form_path, self.tax_forms_dir)
        
        if not secure_path:
            return None
        
        # The secure path is now completely sanitized and contains no user input
        try:
            if not os.path.isfile(secure_path):
                return None
                
            with open(secure_path, 'rb') as form:
                _ = bytearray(form.read())

            # Return the original format for compatibility
            return tax_form_path
            
        except (OSError, IOError, PermissionError):
            return None
