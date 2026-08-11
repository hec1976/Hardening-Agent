.PHONY: install test lint demo clean

install:
	python3 -m pip install -e .

test:
	python3 -m pytest

lint:
	python3 -m ruff check .

demo:
	hardening-agent doctor

clean:
	rm -rf build dist .pytest_cache .ruff_cache
