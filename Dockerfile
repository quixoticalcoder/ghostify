FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements-web.txt .
RUN pip install -r requirements-web.txt
COPY . .
RUN useradd --create-home app && chown -R app:app /app
USER app
ENV PORT=8501 LANGCHAIN_TRACING_V2=false LANGSMITH_TRACING=false
EXPOSE 8501
CMD ["sh", "-c", "exec streamlit run streamlit_app.py --server.address=0.0.0.0 --server.port=${PORT} --server.headless=true --browser.gatherUsageStats=false"]
