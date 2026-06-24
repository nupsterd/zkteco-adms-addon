"""Unit tests del CommandQueue in-memory (PR A.1, ADR-076)."""

from datetime import datetime, timedelta, timezone

from command_queue import Command, CommandQueue


async def test_enqueue_then_get_next_pending_returns_command():
    q = CommandQueue()
    cmd = await q.enqueue("SN1", "CHECK")
    assert isinstance(cmd, Command)
    assert cmd.cmd_id == 1
    assert cmd.sn == "SN1"
    assert cmd.payload == "CHECK"
    assert cmd.delivered_at is None
    assert cmd.acked_at is None

    pending = await q.get_next_pending("SN1")
    assert pending is cmd


async def test_multiple_enqueue_same_sn_is_fifo():
    q = CommandQueue()
    c1 = await q.enqueue("SN1", "CMD_A")
    c2 = await q.enqueue("SN1", "CMD_B")
    c3 = await q.enqueue("SN1", "CMD_C")

    # get_next_pending no marca entregado: siempre devuelve el primero no entregado.
    assert (await q.get_next_pending("SN1")) is c1
    await q.mark_delivered(c1.cmd_id)
    assert (await q.get_next_pending("SN1")) is c2
    await q.mark_delivered(c2.cmd_id)
    assert (await q.get_next_pending("SN1")) is c3
    await q.mark_delivered(c3.cmd_id)
    assert (await q.get_next_pending("SN1")) is None


async def test_multiple_sn_are_isolated():
    q = CommandQueue()
    a = await q.enqueue("SN_A", "CMD_A")
    b = await q.enqueue("SN_B", "CMD_B")

    assert (await q.get_next_pending("SN_A")) is a
    assert (await q.get_next_pending("SN_B")) is b
    # Drenar SN_A no afecta SN_B.
    await q.mark_delivered(a.cmd_id)
    assert (await q.get_next_pending("SN_A")) is None
    assert (await q.get_next_pending("SN_B")) is b


async def test_get_next_pending_unknown_sn_returns_none():
    q = CommandQueue()
    assert (await q.get_next_pending("DESCONOCIDO")) is None


async def test_mark_delivered_and_acked_transitions():
    q = CommandQueue()
    cmd = await q.enqueue("SN1", "DATA QUERY USERINFO")
    assert cmd.delivered_at is None and cmd.acked_at is None

    await q.mark_delivered(cmd.cmd_id)
    assert cmd.delivered_at is not None
    assert cmd.acked_at is None

    await q.mark_acked(cmd.cmd_id)
    assert cmd.acked_at is not None


async def test_mark_delivered_is_idempotent():
    q = CommandQueue()
    cmd = await q.enqueue("SN1", "CHECK")
    await q.mark_delivered(cmd.cmd_id)
    first = cmd.delivered_at
    await q.mark_delivered(cmd.cmd_id)
    assert cmd.delivered_at is first  # no se sobreescribe


async def test_mark_unknown_cmd_id_is_noop():
    q = CommandQueue()
    # No debe levantar.
    await q.mark_delivered(999)
    await q.mark_acked(999)


async def test_cmd_id_autoincrement_unique_across_sns():
    q = CommandQueue()
    a = await q.enqueue("SN_A", "CMD_A")
    b = await q.enqueue("SN_B", "CMD_B")
    c = await q.enqueue("SN_A", "CMD_C")
    assert [a.cmd_id, b.cmd_id, c.cmd_id] == [1, 2, 3]


async def test_get_status_returns_command_or_none():
    q = CommandQueue()
    cmd = await q.enqueue("SN1", "CHECK")
    assert (await q.get_status(cmd.cmd_id)) is cmd
    assert (await q.get_status(12345)) is None


async def test_command_to_dict_serializes_timestamps():
    q = CommandQueue()
    cmd = await q.enqueue("SN1", "CHECK")
    d = cmd.to_dict()
    assert d["cmd_id"] == 1
    assert d["sn"] == "SN1"
    assert d["payload"] == "CHECK"
    assert isinstance(d["enqueued_at"], str)
    assert d["delivered_at"] is None
    assert d["acked_at"] is None

    await q.mark_delivered(cmd.cmd_id)
    await q.mark_acked(cmd.cmd_id)
    d2 = cmd.to_dict()
    assert isinstance(d2["delivered_at"], str)
    assert isinstance(d2["acked_at"], str)


# ---------------------------------------------------------------------------
# PR A.2/A.3: pop_for_delivery, mark_acked con response, UTC, cleanup, size.
# ---------------------------------------------------------------------------


async def test_pop_for_delivery_returns_first_pending_and_marks_delivered():
    q = CommandQueue()
    cmd = await q.enqueue("SN1", "CHECK")
    popped = await q.pop_for_delivery("SN1")
    assert popped is cmd
    assert popped.delivered_at is not None


async def test_pop_for_delivery_fifo_order_with_two_commands():
    q = CommandQueue()
    c1 = await q.enqueue("SN1", "CMD_A")
    c2 = await q.enqueue("SN1", "CMD_B")
    assert (await q.pop_for_delivery("SN1")) is c1
    assert (await q.pop_for_delivery("SN1")) is c2


async def test_pop_for_delivery_returns_none_for_unknown_sn():
    q = CommandQueue()
    assert (await q.pop_for_delivery("DESCONOCIDO")) is None


async def test_pop_for_delivery_returns_none_when_all_delivered():
    q = CommandQueue()
    await q.enqueue("SN1", "CHECK")
    assert (await q.pop_for_delivery("SN1")) is not None
    assert (await q.pop_for_delivery("SN1")) is None


async def test_mark_acked_with_response_stores_ack_response():
    q = CommandQueue()
    cmd = await q.enqueue("SN1", "CHECK")
    await q.pop_for_delivery("SN1")
    await q.mark_acked(cmd.cmd_id, response="ID=1&Return=0")
    got = await q.get_status(cmd.cmd_id)
    assert got.ack_response == "ID=1&Return=0"


async def test_mark_acked_idempotent_does_not_overwrite():
    q = CommandQueue()
    cmd = await q.enqueue("SN1", "CHECK")
    await q.mark_acked(cmd.cmd_id, response="ID=1&Return=0")
    first_acked = cmd.acked_at
    await q.mark_acked(cmd.cmd_id, response="ID=1&Return=99")
    assert cmd.acked_at is first_acked
    assert cmd.ack_response == "ID=1&Return=0"


async def test_mark_acked_backward_compat_no_response_arg():
    q = CommandQueue()
    cmd = await q.enqueue("SN1", "CHECK")
    await q.mark_acked(cmd.cmd_id)  # firma vieja, sin response
    assert cmd.acked_at is not None
    assert cmd.ack_response is None


async def test_to_dict_includes_ack_response():
    q = CommandQueue()
    cmd = await q.enqueue("SN1", "CHECK")
    await q.mark_acked(cmd.cmd_id, response="ID=1&Return=0")
    d = cmd.to_dict()
    assert "ack_response" in d
    assert d["ack_response"] == "ID=1&Return=0"


async def test_timestamps_are_utc_timezone_aware():
    q = CommandQueue()
    cmd = await q.enqueue("SN1", "CHECK")
    await q.pop_for_delivery("SN1")
    await q.mark_acked(cmd.cmd_id, response="ID=1&Return=0")
    assert cmd.enqueued_at.tzinfo == timezone.utc
    assert cmd.delivered_at.tzinfo == timezone.utc
    assert cmd.acked_at.tzinfo == timezone.utc


async def test_cleanup_expired_evicts_acked_older_than_1h():
    q = CommandQueue()
    cmd = await q.enqueue("SN1", "CHECK")
    await q.mark_acked(cmd.cmd_id, response="ID=1&Return=0")
    cmd.acked_at = datetime.now(timezone.utc) - timedelta(hours=2)
    assert (await q.cleanup_expired()) == 1
    assert (await q.get_status(cmd.cmd_id)) is None


async def test_cleanup_expired_evicts_delivered_no_ack_older_than_24h():
    q = CommandQueue()
    cmd = await q.enqueue("SN1", "CHECK")
    await q.pop_for_delivery("SN1")
    cmd.delivered_at = datetime.now(timezone.utc) - timedelta(hours=25)
    assert cmd.acked_at is None
    assert (await q.cleanup_expired()) == 1


async def test_cleanup_expired_evicts_enqueued_only_older_than_7d():
    q = CommandQueue()
    cmd = await q.enqueue("SN1", "CHECK")
    cmd.enqueued_at = datetime.now(timezone.utc) - timedelta(days=8)
    assert cmd.delivered_at is None and cmd.acked_at is None
    assert (await q.cleanup_expired()) == 1


async def test_cleanup_expired_keeps_recent_commands_in_all_3_states():
    q = CommandQueue()
    now = datetime.now(timezone.utc)
    acked = await q.enqueue("SN1", "A")
    await q.mark_acked(acked.cmd_id, response="ID=1&Return=0")
    acked.acked_at = now - timedelta(minutes=30)
    delivered = await q.enqueue("SN1", "B")
    delivered.delivered_at = now - timedelta(hours=1)
    enqueued = await q.enqueue("SN1", "C")
    enqueued.enqueued_at = now - timedelta(hours=1)
    assert (await q.cleanup_expired()) == 0


async def test_cleanup_expired_idempotent_returns_zero_second_call():
    q = CommandQueue()
    cmd = await q.enqueue("SN1", "CHECK")
    await q.mark_acked(cmd.cmd_id, response="ID=1&Return=0")
    cmd.acked_at = datetime.now(timezone.utc) - timedelta(hours=2)
    assert (await q.cleanup_expired()) == 1
    assert (await q.cleanup_expired()) == 0


async def test_size_reflects_queue_state_pre_post_cleanup():
    q = CommandQueue()
    c1 = await q.enqueue("SN1", "A")
    await q.enqueue("SN1", "B")
    await q.enqueue("SN1", "C")
    assert (await q.size()) == 3
    await q.mark_acked(c1.cmd_id, response="ID=1&Return=0")
    c1.acked_at = datetime.now(timezone.utc) - timedelta(hours=2)
    evicted = await q.cleanup_expired()
    assert evicted == 1
    assert (await q.size()) == 2
