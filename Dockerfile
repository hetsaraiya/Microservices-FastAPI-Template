# Use an official Python runtime as a parent image
FROM --platform=linux/amd64 python:3.12.5

# Set the working directory in the container
WORKDIR /usr/backend

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --upgrade pip

# Install Poetry
RUN pip install --no-cache-dir poetry

# Copy only the dependency definitions first
COPY pyproject.toml poetry.lock* /usr/backend/

# Install dependencies (no project root installation)
RUN poetry install --no-root --no-interaction --no-ansi

# Copy the rest of the application code to the container
COPY . /usr/backend/

RUN ls /usr/backend

# Expose the application port
EXPOSE 8000


# Command to run Alembic migrations and then start the application
#poetry run alembic revision --autogenerate -m 'Migration Command' && poetry run alembic upgrade head && poetry run uvicorn main:app --host 0.0.0.0 --port 8000
CMD ["sh", "-c", "poetry run uvicorn src.main:backend_app --host 0.0.0.0 --port 8000"]
