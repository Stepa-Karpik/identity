FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml alembic.ini ./
COPY alembic ./alembic
RUN pip install --no-cache-dir .
COPY app ./app
EXPOSE 8300
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8300"]
