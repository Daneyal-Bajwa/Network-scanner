# Using a lightweight version of Alpine Linux with Python pre-installed
FROM python:3.11-alpine

# Installing the Linux ping utility (Alpine needs this explicitly)
RUN apk add --no-cache iputils

# Setting the working directory inside the container
WORKDIR /app

# Copying the requirements file and install dependencies
COPY requirements.txt .
COPY main.py .
RUN pip install --no-cache-dir -r requirements.txt

# Copying the Python script into the container
COPY scanner.py .
COPY scan_job.py .

# Expose port for FASTAPI
EXPOSE 8000

# Command to run when the container starts
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]