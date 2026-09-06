import os

from django.core.wsgi import get_wsgi_application

from forensics.request_body import count_request_body

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

# Wrap ``wsgi.input`` so the upload API can compare the bytes that actually
# arrived against the client's Content-Length. gunicorn hands Django a silently
# short body when a transfer is cut mid-stream; without this counter a truncated
# multipart upload is indistinguishable from a complete one.
application = count_request_body(get_wsgi_application())
