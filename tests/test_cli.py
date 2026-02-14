"""
SafeNet CLI Tests

Comprehensive test suite for the Typer CLI dashboard.
Tests all commands: status, start, stop, enroll, list, remove.

Running Tests:
    pytest tests/test_cli.py -v
    pytest tests/test_cli.py::test_status_command -v
    pytest tests/test_cli.py -v -s  # with output

Author: SafeNet Testing Team
"""

import pytest
from unittest.mock import patch, Mock, MagicMock
from typer.testing import CliRunner
import requests

# Import the CLI app
import sys
from pathlib import Path

# Add parent directory to path to import cli module
sys.path.insert(0, str(Path(__file__).parent.parent))

from cli.console import app

# Create test runner
runner = CliRunner()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# FIXTURES
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@pytest.fixture
def mock_token():
    """Mock JWT token authentication."""
    with patch('cli.console.get_token') as mock:
        mock.return_value = "mock_jwt_token_12345"
        yield mock


@pytest.fixture
def mock_requests_get():
    """Mock requests.get for API calls."""
    with patch('cli.console.requests.get') as mock:
        yield mock


@pytest.fixture
def mock_requests_post():
    """Mock requests.post for API calls."""
    with patch('cli.console.requests.post') as mock:
        yield mock


@pytest.fixture
def mock_requests_delete():
    """Mock requests.delete for API calls."""
    with patch('cli.console.requests.delete') as mock:
        yield mock


@pytest.fixture
def mock_qr_code():
    """Mock QR code generation."""
    with patch('cli.console.qrcode.QRCode') as mock:
        qr_instance = MagicMock()
        mock.return_value = qr_instance
        yield qr_instance


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# STATUS COMMAND TESTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def test_status_command_gateway_online(mock_token, mock_requests_get):
    """Test status command when gateway is online."""
    # Mock health endpoint response
    health_response = Mock()
    health_response.status_code = 200
    health_response.json.return_value = {"status": "healthy"}
    
    # Mock status endpoint response
    status_response = Mock()
    status_response.status_code = 200
    status_response.json.return_value = {
        "status": "active",
        "message": "Tunnel is running"
    }
    
    mock_requests_get.side_effect = [health_response, status_response]
    
    # Run command
    result = runner.invoke(app, ["status"])
    
    # Assertions
    assert result.exit_code == 0
    assert "HEALTHY" in result.stdout
    assert "ONLINE" in result.stdout


def test_status_command_gateway_offline(mock_token, mock_requests_get):
    """Test status command when gateway is offline."""
    # Mock health endpoint response
    health_response = Mock()
    health_response.status_code = 200
    health_response.json.return_value = {"status": "healthy"}
    
    # Mock status endpoint response
    status_response = Mock()
    status_response.status_code = 200
    status_response.json.return_value = {
        "status": "inactive",
        "message": "Tunnel is not running"
    }
    
    mock_requests_get.side_effect = [health_response, status_response]
    
    # Run command
    result = runner.invoke(app, ["status"])
    
    # Assertions
    assert result.exit_code == 0
    assert "HEALTHY" in result.stdout
    assert "OFFLINE" in result.stdout


def test_status_command_api_unreachable():
    """Test status command when API is unreachable."""
    with patch('cli.console.requests.post') as mock_post:
        mock_post.side_effect = requests.exceptions.ConnectionError()
        
        result = runner.invoke(app, ["status"])
        
        # Should exit with error
        assert result.exit_code == 1
        assert "Connection" in result.stdout


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# START COMMAND TESTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def test_start_command_success(mock_token, mock_requests_post):
    """Test start command successful execution."""
    # Mock start tunnel response
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "message": "Tunnel started with 0 enrolled devices"
    }
    mock_requests_post.return_value = mock_response
    
    # Run command
    result = runner.invoke(app, ["start"])
    
    # Assertions
    assert result.exit_code == 0
    assert "Gateway Started" in result.stdout or "ONLINE" in result.stdout


def test_start_command_access_denied(mock_token, mock_requests_post):
    """Test start command with access denied (not admin)."""
    # Mock access denied response
    mock_response = Mock()
    mock_response.status_code = 500
    mock_response.json.return_value = {
        "detail": "Tunnel start failed: Access denied"
    }
    mock_requests_post.return_value = mock_response
    
    # Run command
    result = runner.invoke(app, ["start"])
    
    # Assertions
    assert result.exit_code == 1
    assert "Failed" in result.stdout or "Error" in result.stdout


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# STOP COMMAND TESTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def test_stop_command_success(mock_token, mock_requests_post):
    """Test stop command successful execution."""
    # Mock stop tunnel response
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "message": "Tunnel stopped successfully"
    }
    mock_requests_post.return_value = mock_response
    
    # Run command
    result = runner.invoke(app, ["stop"])
    
    # Assertions
    assert result.exit_code == 0
    assert "Gateway Stopped" in result.stdout or "OFFLINE" in result.stdout


def test_stop_command_not_running(mock_token, mock_requests_post):
    """Test stop command when gateway not running."""
    # Mock tunnel not running response
    mock_response = Mock()
    mock_response.status_code = 500
    mock_response.json.return_value = {
        "detail": "Tunnel is not running"
    }
    mock_requests_post.return_value = mock_response
    
    # Run command
    result = runner.invoke(app, ["stop"])
    
    # Assertions
    assert result.exit_code == 1


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ENROLL COMMAND TESTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def test_enroll_command_success(mock_token, mock_requests_post, mock_qr_code):
    """Test enroll command successful enrollment."""
    # Mock enrollment response
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "device_name": "test-phone",
        "assigned_ip": "10.8.0.2/24",
        "public_key": "HIgo5A3qKwgVcGMNPh3jLMOtYQ1234567890abcdef=",
        "config_string": "[Interface]\\nPrivateKey=...\\n[Peer]\\n..."
    }
    mock_requests_post.return_value = mock_response
    
    # Run command
    result = runner.invoke(app, ["enroll", "test-phone"])
    
    # Assertions
    assert result.exit_code == 0
    assert "test-phone" in result.stdout
    assert "10.8.0.2" in result.stdout
    
    # Verify QR code was generated
    mock_qr_code.add_data.assert_called_once()
    mock_qr_code.print_tty.assert_called_once()


def test_enroll_command_device_already_exists(mock_token, mock_requests_post):
    """Test enroll command with duplicate device name."""
    # Mock conflict response
    mock_response = Mock()
    mock_response.status_code = 409
    mock_response.json.return_value = {
        "detail": "Device 'test-phone' already exists"
    }
    mock_requests_post.return_value = mock_response
    
    # Run command
    result = runner.invoke(app, ["enroll", "test-phone"])
    
    # Assertions
    assert result.exit_code == 1
    assert "Already Exists" in result.stdout or "Conflict" in result.stdout


def test_enroll_command_invalid_name(mock_token, mock_requests_post):
    """Test enroll command with invalid device name."""
    # Mock validation error response
    mock_response = Mock()
    mock_response.status_code = 422
    mock_response.json.return_value = {
        "detail": "Invalid device name format"
    }
    mock_requests_post.return_value = mock_response
    
    # Run command
    result = runner.invoke(app, ["enroll", "invalid name!@#"])
    
    # Assertions
    assert result.exit_code == 1
    assert "Invalid" in result.stdout or "Validation" in result.stdout


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# LIST COMMAND TESTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def test_list_command_with_devices(mock_token, mock_requests_get):
    """Test list command with enrolled devices."""
    # Mock devices response
    devices_response = Mock()
    devices_response.status_code = 200
    devices_response.json.return_value = {
        "devices": [
            {
                "name": "phone-alice",
                "ip_address": "10.8.0.2",
                "public_key": "HIgo5A3qKwgVcGMNPh3jLMOtYQ1234567890abcdef=",
                "groups": ["default"]
            },
            {
                "name": "laptop-bob",
                "ip_address": "10.8.0.3",
                "public_key": "cNJx4wQZ8T2V0yHTV2T7nd1234567890abcdef=",
                "groups": ["default"]
            }
        ]
    }
    
    # Mock active peers response
    active_response = Mock()
    active_response.status_code = 200
    active_response.json.return_value = {
        "active_peers": [
            {
                "public_key": "HIgo5A3qKwgVcGMNPh3jLMOtYQ1234567890abcdef=",
                "latest_handshake": 1707916800  # Recent handshake
            }
        ]
    }
    
    mock_requests_get.side_effect = [devices_response, active_response]
    
    # Run command
    result = runner.invoke(app, ["list"])
    
    # Assertions
    assert result.exit_code == 0
    assert "phone-alice" in result.stdout
    assert "laptop-bob" in result.stdout
    assert "10.8.0.2" in result.stdout
    assert "10.8.0.3" in result.stdout


def test_list_command_empty_database(mock_token, mock_requests_get):
    """Test list command with no enrolled devices."""
    # Mock empty devices response
    devices_response = Mock()
    devices_response.status_code = 200
    devices_response.json.return_value = {"devices": []}
    
    mock_requests_get.return_value = devices_response
    
    # Run command
    result = runner.invoke(app, ["list"])
    
    # Assertions
    assert result.exit_code == 0
    assert "No devices" in result.stdout or "enrolled yet" in result.stdout


def test_list_command_shows_active_status(mock_token, mock_requests_get):
    """Test list command shows correct active status."""
    import time
    current_time = int(time.time())
    
    # Mock devices response
    devices_response = Mock()
    devices_response.status_code = 200
    devices_response.json.return_value = {
        "devices": [
            {
                "name": "active-device",
                "ip_address": "10.8.0.2",
                "public_key": "ActiveKey123456789012345678901234567890ab=",
                "groups": ["default"]
            }
        ]
    }
    
    # Mock active peers with recent handshake
    active_response = Mock()
    active_response.status_code = 200
    active_response.json.return_value = {
        "active_peers": [
            {
                "public_key": "ActiveKey123456789012345678901234567890ab=",
                "latest_handshake": current_time - 60  # 1 minute ago (active)
            }
        ]
    }
    
    mock_requests_get.side_effect = [devices_response, active_response]
    
    # Run command
    result = runner.invoke(app, ["list"])
    
    # Assertions
    assert result.exit_code == 0
    assert "Active" in result.stdout


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# REMOVE COMMAND TESTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def test_remove_command_success(mock_token, mock_requests_delete):
    """Test remove command successful deletion."""
    # Mock delete response
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "success": True,
        "message": "Device 'test-phone' removed successfully"
    }
    mock_requests_delete.return_value = mock_response
    
    # Run command with confirmation
    result = runner.invoke(app, ["remove", "test-phone"], input="y\n")
    
    # Assertions
    assert result.exit_code == 0
    assert "Removal Complete" in result.stdout or "removed" in result.stdout.lower()


def test_remove_command_cancelled(mock_token, mock_requests_delete):
    """Test remove command when user cancels."""
    # Run command and cancel
    result = runner.invoke(app, ["remove", "test-phone"], input="n\n")
    
    # Assertions
    assert result.exit_code == 0
    assert "cancelled" in result.stdout.lower()
    
    # Verify delete was not called
    mock_requests_delete.assert_not_called()


def test_remove_command_device_not_found(mock_token, mock_requests_delete):
    """Test remove command with non-existent device."""
    # Mock 404 response
    mock_response = Mock()
    mock_response.status_code = 404
    mock_response.json.return_value = {
        "detail": "Device 'unknown-device' not found"
    }
    mock_requests_delete.return_value = mock_response
    
    # Run command with confirmation
    result = runner.invoke(app, ["remove", "unknown-device"], input="y\n")
    
    # Assertions
    assert result.exit_code == 1
    assert "Not Found" in result.stdout or "not found" in result.stdout.lower()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# INTEGRATION TESTS (Requires API Server Running)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@pytest.mark.integration
def test_full_lifecycle_integration():
    """
    Integration test for complete device lifecycle.
    
    Requires:
    - API server running on http://127.0.0.1:8000
    - Administrator privileges (for gateway start)
    
    Run with: pytest tests/test_cli.py::test_full_lifecycle_integration -v -s
    """
    # Note: This is a manual integration test
    # Uncomment and run manually when API server is available
    
    # 1. Check status
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0
    
    # 2. List devices
    result = runner.invoke(app, ["list"])
    assert result.exit_code == 0
    
    # Add more integration steps as needed


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ERROR HANDLING TESTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def test_qr_code_generation_error(mock_token, mock_requests_post):
    """Test enroll command when QR code generation fails."""
    # Mock enrollment response
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "device_name": "test-phone",
        "assigned_ip": "10.8.0.2/24",
        "public_key": "HIgo5A3qKwgVcGMNPh3jLMOtYQ1234567890abcdef=",
        "config_string": "[Interface]\\nPrivateKey=...\\n[Peer]\\n..."
    }
    mock_requests_post.return_value = mock_response
    
    # Mock QR code to raise exception
    with patch('cli.console.qrcode.QRCode') as mock_qr:
        mock_qr.side_effect = Exception("QR generation failed")
        
        result = runner.invoke(app, ["enroll", "test-phone"])
        
        # Should still succeed (QR is optional)
        assert result.exit_code == 0
        assert "QR Code generation failed" in result.stdout


def test_api_timeout():
    """Test command behavior on API timeout."""
    # Timeout occurs during authentication (POST to /api/token)
    with patch('cli.console.requests.post') as mock_post:
        mock_post.side_effect = requests.exceptions.Timeout()
        
        result = runner.invoke(app, ["status"])
        
        assert result.exit_code == 1
        # Check for timeout error message from get_token function
        assert "Timeout" in result.stdout or "timeout" in result.stdout.lower()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# HELPER TESTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def test_help_command():
    """Test help command displays usage information."""
    result = runner.invoke(app, ["--help"])
    
    assert result.exit_code == 0
    assert "status" in result.stdout
    assert "start" in result.stdout
    assert "stop" in result.stdout
    assert "enroll" in result.stdout
    assert "list" in result.stdout
    assert "remove" in result.stdout


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "-s"])
