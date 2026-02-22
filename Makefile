.PHONY: clean media install dev test

# Remove stale native extensions from the source tree.
# maturin develop can leave .so/.pyd files that shadow pure-Python
# wrappers and cause hard-to-debug import issues.
clean:
	find src/ -type f \( -name '*.so' -o -name '*.dylib' -o -name '*.pyd' \) -delete
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	rm -rf build/ dist/ *.egg-info src/*.egg-info

# Build the native media extension into the active venv
media:
	pip install ./crates/vox-media

# Editable install with all extras
install:
	pip install -e '.[dev,media]'

# Full clean rebuild: wipe stale artifacts, then install everything
dev: clean install

test:
	pytest
