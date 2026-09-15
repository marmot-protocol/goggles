from datetime import UTC, datetime, timedelta
from unittest import mock

from django.test import SimpleTestCase

from deploy import prune_nightly


class RetentionScheduleTests(SimpleTestCase):
    def test_pruning_switch_accepts_project_boolean_spellings(self):
        for value, enabled in (
            ("1", True),
            ("true", True),
            ("YES", True),
            ("on", True),
            ("0", False),
            ("false", False),
            ("NO", False),
            ("off", False),
        ):
            with (
                self.subTest(value=value),
                mock.patch.dict("os.environ", {"GOGGLES_PRUNE_ON_STARTUP": value}),
                mock.patch.object(prune_nightly.subprocess, "run") as run,
                mock.patch.object(prune_nightly.time, "sleep", side_effect=InterruptedError),
            ):
                run.return_value.returncode = 0
                with self.assertRaises(InterruptedError):
                    prune_nightly.main()
                self.assertEqual(run.call_count, int(enabled))

    def test_next_run_is_three_utc_across_day_boundary(self):
        for now, seconds in (
            (datetime(2026, 9, 15, 2, 59, 59, tzinfo=UTC), 1),
            (datetime(2026, 9, 15, 3, tzinfo=UTC), 86400),
            (datetime(2026, 9, 15, 23, tzinfo=UTC), 14400),
        ):
            with self.subTest(now=now):
                self.assertEqual(prune_nightly.seconds_until_next_run(now), seconds)
                self.assertEqual(
                    (now + timedelta(seconds=seconds)).hour,
                    3,
                )

    @mock.patch.dict("os.environ", {"GOGGLES_PRUNE_ON_STARTUP": "1"})
    def test_startup_prunes_and_success_waits_until_night(self):
        with (
            mock.patch.object(prune_nightly.subprocess, "run") as run,
            mock.patch.object(prune_nightly, "seconds_until_next_run", return_value=123),
            mock.patch.object(prune_nightly.time, "sleep", side_effect=InterruptedError) as sleep,
        ):
            run.return_value.returncode = 0
            with self.assertRaises(InterruptedError):
                prune_nightly.main()
            run.assert_called_once_with(
                [prune_nightly.sys.executable, "manage.py", "prune_audit_data"]
            )
            sleep.assert_called_once_with(123)

    @mock.patch.dict("os.environ", {"GOGGLES_PRUNE_ON_STARTUP": "1"})
    def test_failure_retries_after_five_minutes(self):
        with (
            mock.patch.object(prune_nightly.subprocess, "run") as run,
            mock.patch.object(
                prune_nightly.time, "sleep", side_effect=[None, InterruptedError]
            ) as sleep,
        ):
            run.return_value.returncode = 1
            with self.assertRaises(InterruptedError):
                prune_nightly.main()
            self.assertEqual(run.call_count, 2)
            self.assertEqual(sleep.call_args_list, [mock.call(300), mock.call(300)])

    @mock.patch.dict("os.environ", {"GOGGLES_PRUNE_ON_STARTUP": "0"})
    def test_cutover_switch_disables_scheduled_pruning(self):
        with (
            mock.patch.object(prune_nightly.subprocess, "run") as run,
            mock.patch.object(prune_nightly.time, "sleep", side_effect=InterruptedError),
        ):
            with self.assertRaises(InterruptedError):
                prune_nightly.main()
            run.assert_not_called()
