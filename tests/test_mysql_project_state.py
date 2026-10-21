import json
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
import unittest
import uuid

from mindhub.migrations import apply_migrations
from mindhub.project_state import ProjectState, ProjectStatePersistenceError


ALLOWED_TEST_DATABASES = frozenset({"mindhub_test"})
REQUIRED_TEST_HOST = "127.0.0.1"
REQUIRED_TEST_PORT = "33307"


def validate_disposable_config(values):
    """Reject any endpoint that is not the approved local disposable target."""
    database = values.get("MINDHUB_TEST_MYSQL_DATABASE")
    host = values.get("MINDHUB_TEST_MYSQL_HOST")
    port = values.get("MINDHUB_TEST_MYSQL_PORT")
    if database not in ALLOWED_TEST_DATABASES:
        raise ValueError("database is not an allowed disposable test database")
    if host != REQUIRED_TEST_HOST or port != REQUIRED_TEST_PORT:
        raise ValueError("MySQL test endpoint must be 127.0.0.1:33307")


class DisposableConfigTests(unittest.TestCase):
    def test_rejects_database_outside_hard_allowlist(self):
        with self.assertRaises(ValueError):
            validate_disposable_config({
                "MINDHUB_TEST_MYSQL_DATABASE": "ai_memory",
                "MINDHUB_TEST_MYSQL_HOST": REQUIRED_TEST_HOST,
                "MINDHUB_TEST_MYSQL_PORT": REQUIRED_TEST_PORT,
            })

    def test_rejects_non_disposable_endpoint(self):
        with self.assertRaises(ValueError):
            validate_disposable_config({
                "MINDHUB_TEST_MYSQL_DATABASE": "mindhub_test",
                "MINDHUB_TEST_MYSQL_HOST": REQUIRED_TEST_HOST,
                "MINDHUB_TEST_MYSQL_PORT": "3306",
            })


class MySQLProjectStateIntegrationTests(unittest.TestCase):
    """Runs only against an explicitly marked disposable MySQL instance."""

    @classmethod
    def setUpClass(cls):
        if os.environ.get("MINDHUB_TEST_MYSQL_DISPOSABLE") != "1":
            raise unittest.SkipTest("set MINDHUB_TEST_MYSQL_DISPOSABLE=1 for disposable MySQL")
        try:
            import mysql.connector  # noqa: F401
        except ModuleNotFoundError:
            raise unittest.SkipTest("mysql-connector-python is not installed")

        from mindhub.mysql_project_state import MySQLProjectStatePersistence

        cls.persistence_class = MySQLProjectStatePersistence
        cls.database = os.environ.get("MINDHUB_TEST_MYSQL_DATABASE")
        required = ("HOST", "PORT", "USER", "PASSWORD")
        if not cls.database or any(not os.environ.get(f"MINDHUB_TEST_MYSQL_{key}") for key in required):
            raise unittest.SkipTest("disposable MySQL connection variables are incomplete")
        validate_disposable_config(os.environ)
        cls.env = {
            "MYSQL_HOST": os.environ["MINDHUB_TEST_MYSQL_HOST"],
            "MYSQL_PORT": os.environ["MINDHUB_TEST_MYSQL_PORT"],
            "MYSQL_DATABASE": cls.database,
            "MYSQL_USER": os.environ["MINDHUB_TEST_MYSQL_USER"],
            "MYSQL_PASSWORD": os.environ["MINDHUB_TEST_MYSQL_PASSWORD"],
        }
        cls.persistence = cls.persistence_class.from_env(cls.env)
        cls._verify_disposable_connection()
        cls._run_migration()

    @classmethod
    def _verify_disposable_connection(cls):
        connection = cls.persistence._connection_factory()
        try:
            cursor = connection.cursor()
            cursor.execute("SELECT DATABASE(), @@port")
            database, server_port = cursor.fetchone()
            if database != "mindhub_test" or int(server_port) != 3306:
                raise RuntimeError("database connection is not the approved disposable instance")
            cls._disposable_connection_verified = True
            cursor.close()
        finally:
            connection.close()

    @classmethod
    def tearDownClass(cls):
        if not getattr(cls, "_disposable_connection_verified", False):
            return
        connection = cls.persistence._connection_factory()
        try:
            cursor = connection.cursor()
            cursor.execute("SELECT DATABASE()")
            if cursor.fetchone()[0] != "mindhub_test":
                raise RuntimeError("refusing cleanup outside mindhub_test")
            cursor.execute("DROP TABLE IF EXISTS project_state_current")
            cursor.execute("DROP TABLE IF EXISTS project_state_snapshots")
            connection.commit()
            cursor.close()
        finally:
            connection.close()

    @classmethod
    def _run_migration(cls):
        connection = cls.persistence._connection_factory()
        try:
            apply_migrations(connection)
        finally:
            connection.close()

    def state(self, project_id=7, **changes):
        values = {
            "project_id": project_id,
            "current_goal": "Validate MySQL persistence",
            "status": "in_progress",
            "progress": "Integration test",
            "updated_at": datetime.now(timezone.utc),
            "decisions": ("Use immutable snapshots",),
            "blockers": (),
            "next_action": "Run disposable test",
        }
        values.update(changes)
        return ProjectState(**values)

    def test_history_current_and_snapshot_ids_are_persistent(self):
        first = self.persistence.create_snapshot(self.state())
        second = self.persistence.create_snapshot(self.state(progress="Committed"))

        self.assertEqual(first.sequence, 1)
        self.assertEqual(second.sequence, 2)
        self.assertNotEqual(first.snapshot_id, second.snapshot_id)
        self.assertEqual(self.persistence.current(7), second)
        self.assertEqual([item.sequence for item in self.persistence.history(7)], [1, 2])
        self.assertEqual(self.persistence.history(7)[0].state.progress, "Integration test")

    def test_concurrent_updates_have_unique_monotonic_sequences(self):
        def write(index):
            return self.persistence.create_snapshot(self.state(11, progress=f"step {index}"))

        with ThreadPoolExecutor(max_workers=8) as executor:
            snapshots = list(executor.map(write, range(20)))

        self.assertEqual(sorted(item.sequence for item in snapshots), list(range(1, 21)))
        self.assertEqual(self.persistence.current(11).sequence, 20)
        self.assertEqual(len(self.persistence.history(11)), 20)

    def test_failed_current_publication_rolls_back_inserted_snapshot(self):
        first = self.persistence.create_snapshot(self.state(19))
        connection = self.persistence._connection_factory()
        trigger_name = f"mindhub_fail_{uuid.uuid4().hex}"
        try:
            cursor = connection.cursor()
            cursor.execute(
                f"CREATE TRIGGER {trigger_name} BEFORE UPDATE ON project_state_current "
                "FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'synthetic failure'"
            )
            connection.commit()
            cursor.close()
        finally:
            connection.close()

        try:
            with self.assertRaises(ProjectStatePersistenceError):
                self.persistence.create_snapshot(self.state(19, progress="must rollback"))
            self.assertEqual(self.persistence.current(19).snapshot_id, first.snapshot_id)
            self.assertEqual(len(self.persistence.history(19)), 1)
        finally:
            connection = self.persistence._connection_factory()
            try:
                cursor = connection.cursor()
                cursor.execute(f"DROP TRIGGER IF EXISTS {trigger_name}")
                connection.commit()
                cursor.close()
            finally:
                connection.close()


if __name__ == "__main__":
    unittest.main()
