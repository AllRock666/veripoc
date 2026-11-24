from unittest.mock import MagicMock
from src.ingestion.schema import VulnClass, Finding
from src.sandbox.runner import SandboxRunner


def test_sandbox_image_selection():
    runner = SandboxRunner(
        image="poc-runner:latest",
        browser_image="poc-runner-browser:latest",
        client=MagicMock(),
    )

    assert runner.get_image(VulnClass.SQLI) == "poc-runner:latest"
    assert runner.get_image(VulnClass.SSRF) == "poc-runner:latest"
    assert runner.get_image(VulnClass.IDOR) == "poc-runner:latest"
    assert runner.get_image(VulnClass.UNKNOWN) == "poc-runner:latest"
    assert runner.get_image(None) == "poc-runner:latest"

    # XSS uses browser image and larger memory limit
    assert runner.get_image(VulnClass.XSS) == "poc-runner-browser:latest"
    assert runner.get_image("xss") == "poc-runner-browser:latest"
    assert runner.get_mem(VulnClass.XSS) == "512m"
    assert runner.get_mem(VulnClass.SQLI) == "256m"


def test_sandbox_run_dispatches_correct_image():
    mock_client = MagicMock()
    mock_container = MagicMock()
    mock_container.wait.return_value = {"StatusCode": 0}
    mock_container.logs.side_effect = [b'{"completed": true, "xss_fired": true}\n', b'']
    mock_client.containers.run.return_value = mock_container

    runner = SandboxRunner(
        image="poc-runner:latest",
        browser_image="poc-runner-browser:latest",
        client=mock_client,
    )

    res = runner.run("print('test')", vuln_class=VulnClass.XSS)

    assert res.exit_code == 0
    assert "xss_fired" in res.stdout
    # Verify container was run with browser image
    mock_client.containers.run.assert_called_once()
    args, kwargs = mock_client.containers.run.call_args
    assert args[0] == "poc-runner-browser:latest"
    assert kwargs["mem_limit"] == "512m"
