FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    tk \
    libx11-6 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV DISPLAY=:0

CMD ["python", "photo_manager/main.py"]