"""Unit tests for CalderaClient with mocked HTTP via respx."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from chef_pantry.clients.caldera import CalderaClient
from chef_pantry.errors import CalderaError, DryRunBlocked

BASE_URL = "http://caldera.local:8888"
API_KEY = "test-api-key"


@pytest.fixture()
def dry_client() -> CalderaClient:
    """CalderaClient in dry-run mode (default)."""
    return CalderaClient(
        base_url=BASE_URL,
        api_key=API_KEY,
        allowed_groups=["sec598-lab"],
        dry_run=True,
    )


@pytest.fixture()
def live_client() -> CalderaClient:
    """CalderaClient with dry-run disabled, for testing actual request paths."""
    return CalderaClient(
        base_url=BASE_URL,
        api_key=API_KEY,
        allowed_groups=["sec598-lab"],
        dry_run=False,
    )


# ---------------------------------------------------------------------------
# list_abilities
# ---------------------------------------------------------------------------


class TestListAbilities:
    @respx.mock
    async def test_returns_list(self, dry_client: CalderaClient) -> None:
        abilities = [
            {"ability_id": "a1", "technique_id": "T1003.001", "name": "Dump LSASS"},
            {"ability_id": "a2", "technique_id": "T1018", "name": "Net Discovery"},
        ]
        respx.get(f"{BASE_URL}/api/v2/abilities").mock(
            return_value=Response(200, json=abilities)
        )
        result = await dry_client.list_abilities()
        assert isinstance(result, list)
        assert len(result) == 2
        assert result[0]["ability_id"] == "a1"

    @respx.mock
    async def test_empty_list(self, dry_client: CalderaClient) -> None:
        respx.get(f"{BASE_URL}/api/v2/abilities").mock(
            return_value=Response(200, json=[])
        )
        result = await dry_client.list_abilities()
        assert result == []


# ---------------------------------------------------------------------------
# find_ability_by_technique
# ---------------------------------------------------------------------------


class TestFindAbilityByTechnique:
    @respx.mock
    async def test_filters_by_technique_id(self, dry_client: CalderaClient) -> None:
        abilities = [
            {"ability_id": "a1", "technique_id": "T1003.001", "name": "Dump LSASS"},
            {"ability_id": "a2", "technique_id": "T1018", "name": "Net Discovery"},
            {"ability_id": "a3", "technique_id": "T1003.001", "name": "ProcDump LSASS"},
        ]
        respx.get(f"{BASE_URL}/api/v2/abilities").mock(
            return_value=Response(200, json=abilities)
        )
        result = await dry_client.find_ability_by_technique("T1003.001")
        assert len(result) == 2
        assert all(a["technique_id"] == "T1003.001" for a in result)

    @respx.mock
    async def test_no_match_returns_empty(self, dry_client: CalderaClient) -> None:
        abilities = [
            {"ability_id": "a1", "technique_id": "T1018", "name": "Net Discovery"},
        ]
        respx.get(f"{BASE_URL}/api/v2/abilities").mock(
            return_value=Response(200, json=abilities)
        )
        result = await dry_client.find_ability_by_technique("T9999")
        assert result == []


# ---------------------------------------------------------------------------
# create_adversary (dry-run behaviour)
# ---------------------------------------------------------------------------


class TestCreateAdversaryDryRun:
    async def test_dry_run_raises_dry_run_blocked(self, dry_client: CalderaClient) -> None:
        with pytest.raises(DryRunBlocked):
            await dry_client.create_adversary(
                name="test-adversary",
                description="test",
                ability_ids=["a1", "a2"],
            )

    async def test_dry_run_property(self, dry_client: CalderaClient) -> None:
        assert dry_client.dry_run is True

    @respx.mock
    async def test_live_mode_sends_request(self, live_client: CalderaClient) -> None:
        expected = {"adversary_id": "adv-1", "name": "test-adversary"}
        respx.post(f"{BASE_URL}/api/v2/adversaries").mock(
            return_value=Response(200, json=expected)
        )
        result = await live_client.create_adversary(
            name="test-adversary",
            description="test",
            ability_ids=["a1"],
        )
        assert result["adversary_id"] == "adv-1"


# ---------------------------------------------------------------------------
# create_operation (group allowlist)
# ---------------------------------------------------------------------------


class TestCreateOperation:
    async def test_disallowed_group_raises_caldera_error(
        self, dry_client: CalderaClient
    ) -> None:
        with pytest.raises(CalderaError) as exc_info:
            await dry_client.create_operation(
                name="op-1",
                adversary_id="adv-1",
                group="production",
            )
        assert exc_info.value.status_code == 403
        assert "production" in exc_info.value.message

    async def test_allowed_group_in_dry_run_raises_dry_run_blocked(
        self, dry_client: CalderaClient
    ) -> None:
        with pytest.raises(DryRunBlocked):
            await dry_client.create_operation(
                name="op-1",
                adversary_id="adv-1",
                group="sec598-lab",
            )

    @respx.mock
    async def test_live_allowed_group_sends_request(
        self, live_client: CalderaClient
    ) -> None:
        expected = {"id": "op-1", "state": "running"}
        respx.post(f"{BASE_URL}/api/v2/operations").mock(
            return_value=Response(200, json=expected)
        )
        result = await live_client.create_operation(
            name="op-1",
            adversary_id="adv-1",
            group="sec598-lab",
        )
        assert result["state"] == "running"


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


class TestErrorHandling:
    @respx.mock
    async def test_4xx_response_raises_caldera_error(
        self, dry_client: CalderaClient
    ) -> None:
        respx.get(f"{BASE_URL}/api/v2/abilities").mock(
            return_value=Response(403, text="Forbidden")
        )
        with pytest.raises(CalderaError) as exc_info:
            await dry_client.list_abilities()
        assert exc_info.value.status_code == 403

    @respx.mock
    async def test_404_response_raises_caldera_error(
        self, dry_client: CalderaClient
    ) -> None:
        respx.get(f"{BASE_URL}/api/v2/abilities/nonexistent").mock(
            return_value=Response(404, text="Not Found")
        )
        with pytest.raises(CalderaError) as exc_info:
            await dry_client.get_ability("nonexistent")
        assert exc_info.value.status_code == 404

    @respx.mock
    async def test_500_response_raises_caldera_error(
        self, dry_client: CalderaClient
    ) -> None:
        respx.get(f"{BASE_URL}/api/v2/abilities").mock(
            return_value=Response(500, text="Internal Server Error")
        )
        with pytest.raises(CalderaError) as exc_info:
            await dry_client.list_abilities()
        assert exc_info.value.status_code == 500

    def test_caldera_error_str_format(self) -> None:
        err = CalderaError(status_code=403, message="Forbidden")
        assert str(err) == "Caldera 403: Forbidden"

    def test_dry_run_blocked_str_with_action(self) -> None:
        err = DryRunBlocked(action="create_adversary")
        assert "DRY RUN" in str(err)
        assert "create_adversary" in str(err)

    def test_dry_run_blocked_str_without_action(self) -> None:
        err = DryRunBlocked()
        assert "DRY RUN" in str(err)


# ---------------------------------------------------------------------------
# Context manager
# ---------------------------------------------------------------------------


class TestContextManager:
    @respx.mock
    async def test_async_context_manager(self) -> None:
        respx.get(f"{BASE_URL}/api/v2/abilities").mock(
            return_value=Response(200, json=[])
        )
        async with CalderaClient(
            base_url=BASE_URL, api_key=API_KEY
        ) as client:
            result = await client.list_abilities()
            assert result == []
