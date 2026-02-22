"""Custom build hooks — clean stale native extensions before editable installs.

maturin develop can leave .so/.pyd files in src/ that shadow pure-Python
wrappers and cause hard-to-debug import failures.  This hooks into both
``pip install -e .`` and ``python setup.py develop`` to wipe them first.
"""

import glob
import os

from setuptools import setup
from setuptools.command.build_py import build_py
from setuptools.command.develop import develop

_STALE_PATTERNS = ("src/**/*.so", "src/**/*.dylib", "src/**/*.pyd")


def _clean_stale_extensions() -> None:
    root = os.path.dirname(os.path.abspath(__file__))
    for pattern in _STALE_PATTERNS:
        for path in glob.glob(os.path.join(root, pattern), recursive=True):
            print(f"removing stale native extension: {path}")
            os.remove(path)


class CleanDevelop(develop):
    def run(self) -> None:
        _clean_stale_extensions()
        super().run()


class CleanBuildPy(build_py):
    def run(self) -> None:
        _clean_stale_extensions()
        super().run()


setup(
    cmdclass={
        "develop": CleanDevelop,
        "build_py": CleanBuildPy,
    },
)
