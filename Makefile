.PHONY: test migrate verify

test:
	.venv/bin/pytest -q
migrate:
	.venv/bin/alembic upgrade head
verify: test
