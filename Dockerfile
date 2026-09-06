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
    && mkdir -p /home/goggles \
    && chown goggles:goggles /home/goggles \
    && mkdir -p /app/staticfiles \
    && chown goggles:goggles /app/staticfiles
USER goggles

EXPOSE 8000

# Threaded workers so a long-running streaming export (the group export endpoint)
# occupies a thread rather than blocking a whole worker; --timeout is raised well
# past a multi-minute stream so gunicorn does not reap it. --max-requests recycles
# workers periodically (gracefully, after in-flight streams finish) for leak hygiene
# now that workers are long-lived. See docs/deployment.md for the capacity model.
# --access-logfile mirrors docker-compose.yml so a bare `docker run` also emits
# per-request status/duration lines (path without query string, no IP or UA).
CMD ["gunicorn", "config.wsgi:application", "--bind", "0.0.0.0:8000", \
     "--workers", "3", "--threads", "4", "--timeout", "300", \
     "--max-requests", "500", "--max-requests-jitter", "50", \
     "--access-logfile", "-", \
     "--access-logformat", "%(t)s \"%(m)s %(U)s\" %(s)s %(B)s %(L)ss cl=%({content-length}i)s platform=%({x-goggles-platform}i)s app=%({x-goggles-app-version}i)s"]
