# V4 cutover inventory checkpoint

Observed on 2026-09-10 UTC with read-only operations. No production deployment,
restart, purge or backup deletion was performed. Counts were read during live
ingestion and are not an atomic reset snapshot; repeat the dry-run after
pausing and draining uploads before requesting deletion approval.

| Existing purge command count | Rows |
| --- | ---: |
| Audit uploads | 13,000 |
| Raw audit events | 957,674 |
| Groups | 568 |
| Saved reports | 0 |
| Upload rejections | 9 |

The command reported `Dry run only; no audit data was deleted.` The updated
command also counts every projection table. It preserves users and credentials.

The detailed operator inventory is maintained outside this public repository.
It includes backup and partial-backup copies, database storage, operational logs,
backup-job coverage, and export ownership gaps. Live database deletion does not
erase those copies. Offsite retention and analyst/downstream exports still need
operator confirmation; no absence of copies is implied by the bounded inventory.

## Verification and deployment gates

`just check` and `just ci` passed on the initial implementation (321 tests on
SQLite and PostgreSQL). Fixtures and Caddy configuration validate. The startup
pruning switch was exercised with mocked commands, without running a real purge.

The committed MDK v4 schema SHA-256 is
`7da683d30c3ab5ae9a11c9998e61634d41cfd242c95bbf01bd98aadc54b60200`.
At this checkpoint, MDK's finalized implementation was still uncommitted.
Record its immutable implementation commit/release and recompare schemas before
deployment. Follow [the staged procedure](deployment.md): deploy the v4-only
boundary first, then perform the historical purge only after separate approval.
