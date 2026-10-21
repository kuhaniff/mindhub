from pathlib import Path
import unittest
from unittest.mock import MagicMock

from mindhub.migrations import apply_migrations, get_migration_sql


class MigrationTests(unittest.TestCase):
    def test_get_migration_sql_loads_project_state_schema(self):
        sql = get_migration_sql()
        self.assertIn("CREATE TABLE IF NOT EXISTS project_state_snapshots", sql)
        self.assertIn("CREATE TABLE IF NOT EXISTS project_state_current", sql)

    def test_get_migration_sql_raises_on_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            get_migration_sql("non_existent_schema.sql")

    def test_apply_migrations_executes_each_statement_and_commits(self):
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor

        sql = "CREATE TABLE t1 (id INT); CREATE TABLE t2 (id INT);"
        executed = apply_migrations(mock_conn, sql=sql)

        self.assertEqual(len(executed), 2)
        self.assertEqual(mock_cursor.execute.call_count, 2)
        mock_conn.commit.assert_called_once()
        mock_cursor.close.assert_called_once()

    def test_apply_migrations_rolls_back_on_error(self):
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.execute.side_effect = RuntimeError("Syntax error")
        mock_conn.cursor.return_value = mock_cursor

        with self.assertRaises(RuntimeError):
            apply_migrations(mock_conn, sql="BAD SQL;")

        mock_conn.rollback.assert_called_once()
        mock_cursor.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
