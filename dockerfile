FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY idm_mcp.py .
ENTRYPOINT ["python", "idm_mcp.py"]