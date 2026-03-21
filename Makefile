# Makefile for Project SafeNet

.PHONY: test install run

test:
	pytest tests/ -v --cov=api --cov=core --cov-report=term-missing

install:
	pip install -r requirements.txt

run:
	python run_api.py
