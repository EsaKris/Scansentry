FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements/ requirements/
RUN pip install --no-cache-dir -r requirements/production.txt
COPY . .
RUN DJANGO_SECRET_KEY=build-only python manage.py collectstatic --noinput --settings=config.settings.local
CMD ["gunicorn", "config.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3", "--timeout", "60"]
