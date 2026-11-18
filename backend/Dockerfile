FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DJANGO_SETTINGS_MODULE=config.settings.production

# Run as an unprivileged user.
RUN useradd --system --create-home --uid 10001 app
WORKDIR /app

COPY requirements/ requirements/
RUN pip install --no-cache-dir -r requirements/production.txt

COPY --chown=app:app . .

# Static files MUST be collected with the production settings: they use a manifest-based storage, and files collected with the
# local settings would make /admin/ fail with "Missing staticfiles manifest entry". The values below exist only so the settings load
# during the build; none of them is used at runtime.
RUN DJANGO_SECRET_KEY="build-only-$(python -c 'import secrets;print(secrets.token_hex(32))')" DJANGO_ALLOWED_HOSTS=build.invalid \
    CORS_ALLOWED_ORIGINS=https://build.invalid ALLOW_LOCAL_CACHE_SINGLE_WORKER=true DATABASE_URL=sqlite:///:memory: \
    python manage.py collectstatic --noinput \
 && mkdir -p /app/media && chown -R app:app /app/media /app/staticfiles

USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD python -c "import os,urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:%s/api/v1/health/' % os.environ.get('PORT','8000'), timeout=4).status == 200 else 1)"
CMD ["gunicorn", "config.wsgi:application", "-c", "gunicorn.conf.py"]
