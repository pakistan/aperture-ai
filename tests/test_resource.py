"""Tests for the resource extractor."""

from aperture.permissions import extract_resource


class TestShellResourceExtraction:
    """Shell command target extraction."""

    def test_rm_extracts_target(self):
        assert extract_resource("shell", "execute", "rm -rf ./build/") == "./build/"

    def test_cat_extracts_file(self):
        assert extract_resource("shell", "execute", "cat /etc/passwd") == "/etc/passwd"

    def test_cp_extracts_destination(self):
        result = extract_resource("shell", "execute", "cp src/main.py dist/main.py")
        assert result == "dist/main.py"

    def test_mv_extracts_destination(self):
        result = extract_resource("shell", "execute", "mv old.txt new.txt")
        assert result == "new.txt"

    def test_chmod_extracts_target(self):
        result = extract_resource("shell", "execute", "chmod 755 deploy.sh")
        assert result == "deploy.sh"

    def test_unknown_command_returns_last_arg(self):
        result = extract_resource("shell", "execute", "custom-tool --flag value")
        assert result == "value"


class TestFilesystemResource:
    """Filesystem scope passthrough."""

    def test_passthrough(self):
        assert extract_resource("filesystem", "read", "src/main.py") == "src/main.py"

    def test_strips_whitespace(self):
        assert extract_resource("filesystem", "write", "  output.txt  ") == "output.txt"


class TestAPIResource:
    """API URL protocol stripping."""

    def test_strips_https(self):
        result = extract_resource("api", "get", "https://api.example.com/users")
        assert result == "api.example.com/users"

    def test_strips_http(self):
        result = extract_resource("api", "post", "http://localhost:8080/health")
        assert result == "localhost:8080/health"

    def test_no_protocol_passthrough(self):
        result = extract_resource("api", "get", "api.example.com/users")
        assert result == "api.example.com/users"


class TestDatabaseResource:
    """SQL table name extraction."""

    def test_select_from(self):
        result = extract_resource("database", "query", "SELECT * FROM users WHERE id = 1")
        assert result == "users"

    def test_insert_into(self):
        result = extract_resource("database", "insert", "INSERT INTO orders VALUES (1, 'test')")
        assert result == "orders"

    def test_drop_table(self):
        result = extract_resource("database", "execute", "DROP TABLE sessions")
        assert result == "sessions"

    def test_no_match_fallback(self):
        result = extract_resource("database", "execute", "VACUUM")
        assert result == "VACUUM"


class TestEdgeCases:
    """Edge cases and empty inputs."""

    def test_empty_scope(self):
        assert extract_resource("shell", "execute", "") == ""

    def test_unknown_tool(self):
        result = extract_resource("custom", "action", "some scope")
        assert result == "some scope"
