import httpx
import respx

from mail_sovereignty.tenant import check_microsoft_tenant


REALM_URL = "https://login.microsoftonline.com/getuserrealm.srf"


class TestCheckMicrosoftTenant:
    @respx.mock
    async def test_managed_tenant(self):
        respx.get(REALM_URL).mock(
            return_value=httpx.Response(
                200, json={"NameSpaceType": "Managed", "DomainName": "example.ch"}
            )
        )
        async with httpx.AsyncClient() as client:
            result = await check_microsoft_tenant(client, "example.ch")
        assert result == "Managed"

    @respx.mock
    async def test_federated_tenant(self):
        respx.get(REALM_URL).mock(
            return_value=httpx.Response(
                200, json={"NameSpaceType": "Federated", "DomainName": "example.ch"}
            )
        )
        async with httpx.AsyncClient() as client:
            result = await check_microsoft_tenant(client, "example.ch")
        assert result == "Federated"

    @respx.mock
    async def test_unknown_domain(self):
        respx.get(REALM_URL).mock(
            return_value=httpx.Response(
                200, json={"NameSpaceType": "Unknown", "DomainName": "nope.ch"}
            )
        )
        async with httpx.AsyncClient() as client:
            result = await check_microsoft_tenant(client, "nope.ch")
        assert result is None

    @respx.mock
    async def test_network_error(self):
        respx.get(REALM_URL).mock(side_effect=httpx.ConnectError("connection refused"))
        async with httpx.AsyncClient() as client:
            result = await check_microsoft_tenant(client, "fail.ch")
        assert result is None

    @respx.mock
    async def test_http_error(self):
        respx.get(REALM_URL).mock(return_value=httpx.Response(500))
        async with httpx.AsyncClient() as client:
            result = await check_microsoft_tenant(client, "error.ch")
        assert result is None

    @respx.mock
    async def test_invalid_json(self):
        respx.get(REALM_URL).mock(
            return_value=httpx.Response(200, text="not json at all")
        )
        async with httpx.AsyncClient() as client:
            result = await check_microsoft_tenant(client, "badjson.ch")
        assert result is None
