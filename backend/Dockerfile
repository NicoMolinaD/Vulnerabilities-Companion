# Backend Dockerfile
FROM python:3.11-slim

# Evitar que Python genere archivos .pyc
ENV PYTHONDONTWRITEBYTECODE 1
# Evitar que Python use buffer para logs
ENV PYTHONUNBUFFERED 1

WORKDIR /app

# Instalar dependencias del sistema si son necesarias
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Instalar dependencias de Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el código del backend
COPY . .

# Exponer el puerto
EXPOSE 8000

# Comando para arrancar la aplicación
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
