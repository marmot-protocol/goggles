FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PATH="/app/.venv/bin:$PATH"

WORKDIR /app

RUN pip install --no-cache-dir uv

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

COPY . .

# Drop privileges: run gunicorn (and anything spawned from request handling) as a
# non-root user. collectstatic writes to STATIC_ROOT (/app/staticfiles), so only
# that runtime-writable directory is owned by the application user.
RUN useradd --system --uid 10001 --no-create-home goggles \
    && mkdir -p /app/staticfiles \
    && chown goggles:goggles /app/staticfiles
USER goggles

EXPOSE 8000

CMD ["gunicorn", "config.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3"]
