import os
import sys
import re
import shutil
import tempfile
import subprocess
from typing import Optional, Tuple, List
from urllib.parse import urlparse, urlunparse, parse_qs
import requests


class ValidationError(Exception):
    pass


class DownloadError(Exception):
    pass


class ExecutionError(Exception):
    pass


def validate_url(url: str, max_length: int = 2048) -> str:
    """
    Validate that the URL is HTTPS and well-formed.
    Returns a normalized URL string.
    """
    if not isinstance(url, str):
        raise ValidationError("URL must be a string.")
    url = url.strip()
    if not url:
        raise ValidationError("URL is empty.")
    if len(url) > max_length:
        raise ValidationError("URL exceeds maximum allowed length.")

    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        raise ValidationError("Only HTTPS URLs are allowed.")
    if not parsed.netloc:
        raise ValidationError("URL must include a valid host.")
    # Forbid userinfo to avoid ambiguity and potential credential leaks
    if "@" in parsed.netloc:
        raise ValidationError("Credentials in URL are not allowed.")

    # Normalize: lowercase scheme and host; keep path/query/fragment as-is
    normalized = parsed._replace(scheme="https", netloc=parsed.netloc.lower())
    return urlunparse(normalized)


def ensure_base_dir(base_dir: str) -> str:
    """
    Ensure base_dir exists, is absolute, is not a symlink, and is a directory.
    Create it if missing with restrictive permissions where possible.
    """
    if not isinstance(base_dir, str) or not base_dir.strip():
        raise ValidationError("Base directory must be a non-empty string.")
    base_dir = os.path.abspath(base_dir)
    # Reject symlink for base dir
    if os.path.islink(base_dir):
        raise ValidationError("Base directory cannot be a symlink.")
    if not os.path.exists(base_dir):
        # Create with restrictive permissions when possible
        os.makedirs(base_dir, exist_ok=False)
        try:
            if os.name != "nt":
                os.chmod(base_dir, 0o700)
        except Exception:
            # If chmod fails (e.g., on Windows), continue
            pass
    if not os.path.isdir(base_dir):
        raise ValidationError("Base path is not a directory.")
    return base_dir


def sanitize_filename(name: str, default_name: str = "program.exe", max_length: int = 128) -> str:
    """
    Sanitize a potentially unsafe filename into a safe one within constraints.
    Ensures .exe extension and removes path components.
    """
    if not isinstance(name, str):
        return default_name
    # Extract the last path component only
    name = os.path.basename(name.strip())
    if not name:
        name = default_name

    # Keep only safe chars
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    # Enforce .exe extension
    if not safe.lower().endswith(".exe"):
        safe = f"{safe}.exe"
    # Truncate to max length while preserving extension if possible
    if len(safe) > max_length:
        root, ext = os.path.splitext(safe)
        allowed_root_len = max(1, max_length - len(ext))
        safe = root[:allowed_root_len] + ext
    # Avoid reserved names on Windows
    reserved = {
        "con", "prn", "aux", "nul",
        *(f"com{i}" for i in range(1, 10)),
        *(f"lpt{i}" for i in range(1, 10)),
    }
    root_name = os.path.splitext(safe)[0].lower()
    if root_name in reserved:
        safe = f"_{safe}"
    return safe


def _derive_filename_from_url(url: str) -> str:
    parsed = urlparse(url)
    candidate = os.path.basename(parsed.path)
    if not candidate:
        # Try from query (e.g., Google Drive may not have a filename in path)
        qs = parse_qs(parsed.query)
        if "filename" in qs and qs["filename"]:
            candidate = qs["filename"][0]
        else:
            candidate = "program.exe"
    return sanitize_filename(candidate)


def _resolve_within_base(base_dir: str, filename: str) -> str:
    """
    Resolve filename within base_dir, ensuring the result stays inside the base.
    """
    if not filename or filename.strip() == "":
        raise ValidationError("Filename must be non-empty.")
    base_dir = ensure_base_dir(base_dir)
    # No directory separators allowed in filename after sanitization
    if os.path.sep in filename or (os.path.altsep and os.path.altsep in filename):
        raise ValidationError("Filename must not contain directory separators.")
    target = os.path.abspath(os.path.join(base_dir, filename))
    # Ensure within base
    base_dir_real = os.path.realpath(base_dir)
    target_real = os.path.realpath(target)
    if not target_real.startswith(base_dir_real + os.sep) and target_real != base_dir_real:
        raise ValidationError("Resolved path escapes the base directory.")
    return target


def _is_google_drive_url(url: str) -> bool:
    host = urlparse(url).netloc.lower()
    return host.endswith("drive.google.com") or host.endswith("docs.google.com")


def _extract_gdrive_id(url: str) -> Optional[str]:
    """
    Extract Google Drive file ID from common URL patterns.
    """
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    if "id" in qs and qs["id"]:
        return qs["id"][0]
    # Patterns like /file/d/<id>/view or /uc?id=<id>
    m = re.search(r"/file/d/([A-Za-z0-9_-]{10,})", parsed.path)
    if m:
        return m.group(1)
    return None


def _build_gdrive_direct_url(file_id: str) -> str:
    return f"https://drive.google.com/uc?export=download&id={file_id}"


def _maybe_follow_gdrive_confirm(session: requests.Session, response: requests.Response, file_id: str, timeout: Tuple[int, int]) -> requests.Response:
    """
    Handle Google Drive 'too large for virus scan' confirm token flow.
    """
    ct = response.headers.get("Content-Type", "").lower()
    if "text/html" not in ct:
        return response

    text = ""
    try:
        # Read a limited amount to search for confirm token
        text = response.text
    except Exception:
        return response

    token_match = re.search(r"confirm=([0-9A-Za-z_]+)", text)
    if not token_match:
        # Cookie-based method
        for k, v in response.cookies.items():
            if k.startswith("download_warning"):
                token_match = re.search(r"(.+)", v)
                break
    if not token_match:
        return response

    token = token_match.group(1)
    confirm_url = f"https://drive.google.com/uc?export=download&id={file_id}&confirm={token}"
    response.close()
    new_resp = session.get(confirm_url, stream=True, timeout=timeout, allow_redirects=True)
    new_resp.raise_for_status()
    return new_resp


def _check_content_length(headers: dict, max_bytes: int) -> None:
    cl = headers.get("Content-Length")
    if cl is None:
        return
    try:
        size = int(cl)
    except ValueError:
        return
    if size > max_bytes:
        raise DownloadError("Remote file exceeds maximum allowed size.")


def _write_stream_to_temp(base_dir: str, response: requests.Response, final_filename: str, max_bytes: int) -> str:
    """
    Write the response body to a temp file inside base_dir, then atomically rename to final file.
    Returns the final absolute file path.
    """
    base_dir = ensure_base_dir(base_dir)
    final_path = _resolve_within_base(base_dir, final_filename)

    # Create a temp file in the same directory to allow atomic rename
    fd, temp_path = tempfile.mkstemp(prefix="dl_", suffix=".tmp", dir=base_dir)
    os.close(fd)  # Re-open with context manager
    total = 0
    first_two = b""

    try:
        with open(temp_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=64 * 1024):
                if not chunk:
                    continue
                total += len(chunk)
                if total > max_bytes:
                    raise DownloadError("Downloaded data exceeds maximum allowed size.")
                # record first two bytes for "MZ" check
                if len(first_two) < 2:
                    needed = 2 - len(first_two)
                    first_two += chunk[:needed]
                f.write(chunk)
            f.flush()
            os.fsync(f.fileno())

        # Validate EXE magic header (PE files start with 'MZ')
        if first_two != b"MZ":
            # As a fallback, open the file and re-check in case first chunk boundary misaligned
            try:
                with open(temp_path, "rb") as rf:
                    magic = rf.read(2)
                if magic != b"MZ":
                    raise DownloadError("Downloaded file is not a valid Windows executable (missing MZ header).")
            except Exception as e:
                raise DownloadError(str(e)) from e

        # Set executable permissions (best-effort, Windows ignores POSIX perms)
        try:
            if os.name != "nt":
                os.chmod(temp_path, 0o700)
        except Exception:
            pass

        # Atomic replace to final path
        os.replace(temp_path, final_path)
        return final_path
    except Exception:
        # Clean up temp file on failure
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except Exception:
            pass
        raise


def download_exe(url: str, base_dir: str, filename: Optional[str] = None, max_bytes: int = 100 * 1024 * 1024, timeout: Tuple[int, int] = (20, 120)) -> str:
    """
    Download an EXE from a given HTTPS URL into base_dir with safe handling.
    Returns the absolute path to the downloaded EXE.
    """
    safe_url = validate_url(url)
    base_dir = ensure_base_dir(base_dir)
    if not isinstance(max_bytes, int) or max_bytes <= 0:
        raise ValidationError("max_bytes must be a positive integer.")

    if filename:
        final_filename = sanitize_filename(filename)
    else:
        final_filename = _derive_filename_from_url(safe_url)

    final_path = _resolve_within_base(base_dir, final_filename)

    headers = {
        "User-Agent": "SecureExeDownloader/1.0",
        "Accept": "application/octet-stream,application/x-msdownload,*/*",
    }

    session = requests.Session()
    session.verify = True  # Ensure TLS verification
    url_to_get = safe_url

    try:
        if _is_google_drive_url(safe_url):
            fid = _extract_gdrive_id(safe_url)
            if fid:
                url_to_get = _build_gdrive_direct_url(fid)

        resp = session.get(url_to_get, stream=True, timeout=timeout, allow_redirects=True, headers=headers)
        resp.raise_for_status()

        # Handle Google Drive confirm flow if needed
        if _is_google_drive_url(url_to_get):
            fid = _extract_gdrive_id(url_to_get) or _extract_gdrive_id(safe_url)
            if fid:
                resp = _maybe_follow_gdrive_confirm(session, resp, fid, timeout)

        _check_content_length(resp.headers, max_bytes)
        path = _write_stream_to_temp(base_dir, resp, os.path.basename(final_path), max_bytes)
        return path
    except (requests.RequestException, OSError) as e:
        raise DownloadError(f"Download failed: {str(e)}") from e
    finally:
        try:
            resp.close()  # type: ignore[name-defined]
        except Exception:
            pass
        session.close()


def is_windows_exe(file_path: str) -> bool:
    """
    Check if a file begins with 'MZ' magic.
    """
    try:
        with open(file_path, "rb") as f:
            sig = f.read(2)
            return sig == b"MZ"
    except Exception:
        return False


def execute_exe(exe_path: str, args: Optional[List[str]] = None, timeout: Optional[int] = None, working_dir: Optional[str] = None) -> int:
    """
    Execute the downloaded EXE program with optional arguments.
    Returns the process exit code.
    Executes only on Windows platforms for safety and compatibility.
    """
    if not isinstance(exe_path, str) or not exe_path:
        raise ExecutionError("Invalid executable path.")
    if os.name != "nt":
        raise ExecutionError("Execution of .exe files is supported only on Windows environments.")
    abs_path = os.path.abspath(exe_path)
    if not os.path.isfile(abs_path):
        raise ExecutionError("Executable file does not exist.")
    if os.path.islink(abs_path):
        raise ExecutionError("Refusing to execute a symlink.")
    if not is_windows_exe(abs_path):
        raise ExecutionError("File is not a valid Windows executable.")

    # Determine working directory
    if working_dir:
        wd = os.path.abspath(working_dir)
    else:
        wd = os.path.dirname(abs_path) or os.getcwd()

    if not os.path.isdir(wd):
        raise ExecutionError("Working directory does not exist.")

    cmd = [abs_path]
    if args:
        if not isinstance(args, list) or any(not isinstance(a, str) for a in args):
            raise ExecutionError("Arguments must be a list of strings.")
        cmd.extend(args)

    try:
        # Do not use shell=True to avoid injection risks
        completed = subprocess.run(cmd, cwd=wd, timeout=timeout, check=False)
        return int(completed.returncode)
    except subprocess.TimeoutExpired as e:
        raise ExecutionError(f"Process timed out after {timeout} seconds.") from e
    except Exception as e:
        raise ExecutionError(f"Execution failed: {str(e)}") from e


def main() -> int:
    """
    Five test cases demonstrating validation and safe behaviors.
    Network and execution are not performed by default to keep tests safe and offline.
    Set environment variable ALLOW_NETWORK=1 to enable the network download demo (if on Windows).
    """
    print("Running tests...")
    test_results = []

    # Prepare a temporary base directory
    base_dir = tempfile.mkdtemp(prefix="exe_dl_test_")
    try:
        # Test 1: Valid HTTPS URL normalization
        try:
            u1 = validate_url("https://EXAMPLE.com/path/to/app.exe?x=1")
            test_results.append(("Test1_ValidateHTTPS", True, u1))
        except Exception as e:
            test_results.append(("Test1_ValidateHTTPS", False, str(e)))

        # Test 2: Reject non-HTTPS URL
        try:
            validate_url("http://example.com/app.exe")
            test_results.append(("Test2_RejectHTTP", False, "Expected failure but passed"))
        except ValidationError as e:
            test_results.append(("Test2_RejectHTTP", True, str(e)))
        except Exception as e:
            test_results.append(("Test2_RejectHTTP", False, str(e)))

        # Test 3: Filename sanitization against path traversal
        try:
            fn = sanitize_filename("../../evil?name*.exe")
            inside = _resolve_within_base(base_dir, fn)
            ok = inside.startswith(os.path.abspath(base_dir))
            test_results.append(("Test3_SanitizeAndResolve", ok, inside))
        except Exception as e:
            test_results.append(("Test3_SanitizeAndResolve", False, str(e)))

        # Test 4: Create a small dummy 'MZ' file and detect as EXE
        try:
            dummy_path = os.path.join(base_dir, "dummy.exe")
            with open(dummy_path, "wb") as f:
                f.write(b"MZ")  # minimal signature
                f.write(b"\x00" * 10)
            test_results.append(("Test4_IsWindowsExe", is_windows_exe(dummy_path), dummy_path))
        except Exception as e:
            test_results.append(("Test4_IsWindowsExe", False, str(e)))

        # Test 5: Execution guard on non-Windows or invalid path
        try:
            if os.name != "nt":
                # Expect failure due to platform guard
                try:
                    execute_exe(dummy_path)
                    test_results.append(("Test5_ExecuteGuard", False, "Expected platform guard failure"))
                except ExecutionError as e:
                    test_results.append(("Test5_ExecuteGuard", True, str(e)))
            else:
                # On Windows, attempt to execute a benign non-existent file to trigger a controlled error
                try:
                    execute_exe(os.path.join(base_dir, "does_not_exist.exe"))
                    test_results.append(("Test5_ExecuteInvalidPath", False, "Expected invalid path failure"))
                except ExecutionError as e:
                    test_results.append(("Test5_ExecuteInvalidPath", True, str(e)))
        except Exception as e:
            test_results.append(("Test5_ExecuteGuard", False, str(e)))

        # Optional network download demo (disabled by default)
        if os.environ.get("ALLOW_NETWORK") == "1":
            try:
                # Provide a valid direct HTTPS URL to a small .exe if you enable this test.
                # For safety, this block is skipped unless explicitly allowed.
                demo_url = "https://example.com/path/to/small.exe"
                # This will likely fail (placeholder URL), but demonstrates path and error handling.
                path = download_exe(demo_url, base_dir)
                test_results.append(("Demo_Download", True, path))
                # Execute only on Windows and only if file exists and is valid
                if os.name == "nt" and os.path.isfile(path) and is_windows_exe(path):
                    rc = execute_exe(path, args=[], timeout=10)
                    test_results.append(("Demo_Execute", True, f"ExitCode={rc}"))
                else:
                    test_results.append(("Demo_Execute", True, "Skipped (platform or file invalid)"))
            except Exception as e:
                test_results.append(("Demo_Download", False, str(e)))
        else:
            test_results.append(("Demo_Skipped", True, "Set ALLOW_NETWORK=1 to enable network demo"))

        # Print results
        for name, ok, info in test_results:
            status = "PASS" if ok else "FAIL"
            print(f"{name}: {status} - {info}")
        return 0
    finally:
        try:
            shutil.rmtree(base_dir)
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())