"""Imported first by every test module: never read or write the user's burpzip.ini."""
import os
import tempfile

os.environ["BURPZIP_CONFIG"] = os.path.join(
    tempfile.gettempdir(), f"burpzip-test-config-{os.getpid()}-absent.ini")
