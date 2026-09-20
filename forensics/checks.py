from django.core.checks import Error, Tags, register
from django.db import connections


@register(Tags.database, deploy=True)
def ingestion_database_version(app_configs, databases=None, **kwargs):
    errors = []
    for alias in databases or []:
        connection = connections[alias]
        if connection.vendor == "postgresql" and connection.pg_version < 170000:
            errors.append(
                Error(
                    "Audit ingestion requires PostgreSQL 17 or later for transaction_timeout.",
                    id="forensics.E001",
                )
            )
    return errors
