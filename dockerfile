# Dockerfile

# Use official Python image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy project files
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Run setup scripts
RUN python setup_crypto_env.py && python setup_database.py

# Expose Flask port
EXPOSE 5000

# Start the app
CMD ["python", "app.py"]
