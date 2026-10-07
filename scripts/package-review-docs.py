"""Compatibility entrypoint: build only explicitly reviewed public files."""
import runpy
from pathlib import Path

runpy.run_path(str(Path(__file__).with_name('build-public.py')), run_name='__main__')
