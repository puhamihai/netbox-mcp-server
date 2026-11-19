"""Tests for the image-attachment upload tool and the device-bay whitelist."""

from unittest.mock import MagicMock, patch

import pytest

from netbox_mcp_server.server import (
    WRITE_ALLOWED_CREATE,
    WRITE_ALLOWED_UPDATE,
    _assert_writable,
    netbox_upload_image_attachment,
)

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32


@pytest.fixture
def png_file(tmp_path):
    path = tmp_path / "front.png"
    path.write_bytes(PNG)
    return path


@pytest.fixture
def mock_netbox():
    with patch("netbox_mcp_server.server.netbox") as nb:
        nb.upload.return_value = {"id": 1, "image": "https://nb/media/front.png"}
        yield nb


def test_devicebay_is_creatable_and_updatable():
    _assert_writable("dcim.devicebay", WRITE_ALLOWED_CREATE, "create")
    _assert_writable("dcim.devicebay", WRITE_ALLOWED_UPDATE, "update")


def test_upload_sends_multipart_with_object_reference(png_file, mock_netbox):
    result = netbox_upload_image_attachment("dcim.device", 1001, str(png_file), name="Front")

    assert result["id"] == 1
    endpoint, data = mock_netbox.upload.call_args.args[:2]
    files = mock_netbox.upload.call_args.kwargs["files"]
    assert endpoint == "extras/image-attachments"
    assert data == {"object_type": "dcim.device", "object_id": "1001", "name": "Front"}
    filename, _, mime = files["image"]
    assert (filename, mime) == ("front.png", "image/png")


def test_upload_resolves_device_name(png_file, mock_netbox):
    with patch("netbox_mcp_server.server._resolve_device", return_value=42) as resolve:
        netbox_upload_image_attachment("dcim.device", "chassis01", str(png_file))
    resolve.assert_called_once_with("chassis01")
    assert mock_netbox.upload.call_args.args[1]["object_id"] == "42"


def test_upload_refuses_unlisted_object_type(png_file, mock_netbox):
    with pytest.raises(ValueError, match="only be attached to"):
        netbox_upload_image_attachment("ipam.prefix", 1, str(png_file))
    mock_netbox.upload.assert_not_called()


def test_upload_refuses_non_image_extension(tmp_path, mock_netbox):
    secret = tmp_path / "id_rsa"
    secret.write_bytes(b"not an image, e.g. a private key")
    with pytest.raises(ValueError, match="Only image files"):
        netbox_upload_image_attachment("dcim.device", 1, str(secret))
    mock_netbox.upload.assert_not_called()


def test_upload_refuses_renamed_non_image(tmp_path, mock_netbox):
    fake = tmp_path / "notes.png"
    fake.write_bytes(b"just text pretending to be a png")
    with pytest.raises(ValueError, match="does not look like"):
        netbox_upload_image_attachment("dcim.device", 1, str(fake))
    mock_netbox.upload.assert_not_called()


def test_upload_refuses_missing_file(tmp_path, mock_netbox):
    with pytest.raises(ValueError, match="No such file"):
        netbox_upload_image_attachment("dcim.device", 1, str(tmp_path / "gone.png"))


def test_upload_refuses_oversized_file(png_file, mock_netbox):
    with (
        patch("netbox_mcp_server.server.IMAGE_MAX_BYTES", 10),
        pytest.raises(ValueError, match="Image must be"),
    ):
        netbox_upload_image_attachment("dcim.device", 1, str(png_file))


def test_client_upload_drops_json_content_type():
    from netbox_mcp_server.netbox_client import NetBoxRestClient

    client = NetBoxRestClient("https://nb.example", "abc123", verify_ssl=False)
    response = MagicMock(is_error=False)
    response.json.return_value = {"id": 7}
    with patch("netbox_mcp_server.netbox_client.httpx.post", return_value=response) as post:
        assert client.upload(
            "extras/image-attachments", {"a": "1"}, {"image": ("x", b"", "image/png")}
        ) == {"id": 7}
    headers = post.call_args.kwargs["headers"]
    assert "Content-Type" not in headers
    assert headers["Authorization"] == "Token abc123"
    assert post.call_args.args[0] == "https://nb.example/api/extras/image-attachments/"


def test_upload_refuses_name_over_netbox_limit(png_file, mock_netbox):
    with pytest.raises(ValueError, match="NetBox allows 50"):
        netbox_upload_image_attachment("dcim.device", 1, str(png_file), name="x" * 51)
    mock_netbox.upload.assert_not_called()


def test_upload_passes_description(png_file, mock_netbox):
    netbox_upload_image_attachment(
        "dcim.device", 1, str(png_file), name="Front", description="by J. Smith, CHG-1234"
    )
    assert mock_netbox.upload.call_args.args[1]["description"] == "by J. Smith, CHG-1234"


def test_client_upload_error_includes_body():
    import httpx

    from netbox_mcp_server.netbox_client import NetBoxRestClient

    client = NetBoxRestClient("https://nb.example", "abc123", verify_ssl=False)
    response = MagicMock(is_error=True, status_code=400, text='{"name": ["too long"]}')
    with (
        patch("netbox_mcp_server.netbox_client.httpx.post", return_value=response),
        pytest.raises(httpx.HTTPStatusError, match="too long"),
    ):
        client.upload("extras/image-attachments", {}, {"image": ("x", b"", "image/png")})
