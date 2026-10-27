FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd --system --home /app --shell /usr/sbin/nologin certmgr
USER certmgr

EXPOSE 8443

CMD ["python", "scripts/serve.py"]
