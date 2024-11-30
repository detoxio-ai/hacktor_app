# Pull official base image
FROM python:3.11.2-slim-buster

# Create a user called dtx
RUN useradd -m  dtx

# Set work directory
WORKDIR /home/dtx/app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Install dependencies
RUN apt-get update && apt-get install -y curl

# Switch to user dtx
USER dtx

# Install Poetry
RUN curl -sSL https://install.python-poetry.org | python3 -

# Add Poetry to PATH
ENV PATH="/home/dtx/.local/bin:$PATH"

# Copy Poetry lock file and pyproject.toml
COPY --chown=dtx:dtx pyproject.toml poetry.lock ./

# Install project dependencies
RUN poetry install --no-root --only main

# Copy the project files
COPY --chown=dtx:dtx . .

# Define the command to run the application
# CMD ["poetry", "run", "streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]

CMD ["poetry", "run", "python", "gradio_app.py"]
