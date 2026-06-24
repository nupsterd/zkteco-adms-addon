"""Unit tests del CommandQueue in-memory (PR A.1, ADR-076)."""

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
