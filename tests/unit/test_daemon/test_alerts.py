import asyncio
import json

import pytest

from secureagentnet.daemon.alerts import AlertManager
from secureagentnet.daemon.config import DaemonSettings


@pytest.fixture
def alert_manager(tmp_path):
    settings = DaemonSettings(data_dir=tmp_path)
    return AlertManager(settings=settings)


@pytest.mark.asyncio
async def test_alert_persisted_and_broadcast(alert_manager):
    queue = await alert_manager.subscribe()
    await alert_manager.emit(
        severity="CRITICAL",
        title="Test Alert",
        message="Test message",
        notify_desktop=False,
    )
    alert = await asyncio.wait_for(queue.get(), timeout=1.0)
    assert alert["severity"] == "CRITICAL"
    assert alert["title"] == "Test Alert"
    assert len(alert_manager.recent_alerts(limit=10)) == 1


def test_recent_alerts_limit(alert_manager):
    asyncio.run(alert_manager.emit("INFO", "A", "a", notify_desktop=False))
    asyncio.run(alert_manager.emit("INFO", "B", "b", notify_desktop=False))
    alerts = alert_manager.recent_alerts(limit=1)
    assert len(alerts) == 1
    assert alerts[0]["title"] == "B"
