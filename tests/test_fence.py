import math
from datetime import datetime, timedelta, timezone

import pytest

from geo.fence import (
    fence_batch,
    haversine,
    impossible_travel,
    require_step_up,
    timezone_shift,
    travel_speed,
    trusted_region,
    validate_policy,
)

UTC = timezone.utc
TOL = 1e-9


def _event(event_id, lat, lon, ts=None, tz="UTC+00:00", risks=()):
    return {
        "id": event_id,
        "lat": lat,
        "lon": lon,
        "ts": ts,
        "tz": tz,
        "ip": "198.51.100.10",
        "risks": list(risks),
    }


def _policy(**changes):
    policy = {
        "max_speed_kmh": 1000.0,
        "regions": ["198.51.100.0/24"],
        "risk_weights": {"new_device": 1, "unusual_time": 1},
        "step_up_threshold": 2,
    }
    policy.update(changes)
    return policy


def test_haversine_high_latitude_not_planar():
    """缺陷 1：高纬度距离不能用平面近似。"""
    distance = haversine((80.0, 0.0), (80.0, 1.0))
    assert distance == pytest.approx(19.30858536350019, rel=0, abs=TOL)


def test_haversine_converts_degrees_to_radians():
    """缺陷 2：角度必须先转弧度，否则量级错误。"""
    distance = haversine((0.0, 0.0), (0.0, 1.0))
    assert distance == pytest.approx(111.1950802335329, rel=0, abs=TOL)


def test_travel_speed_divides_by_hours_not_minutes():
    """缺陷 3：速度以小时为单位，不能按分钟相除。"""
    start = datetime(2026, 1, 1, 8, 0, tzinfo=UTC)
    end = start + timedelta(minutes=90)
    assert travel_speed(start, end, 750.0, None) == pytest.approx(
        500.0, rel=0, abs=TOL
    )
    assert travel_speed(None, None, 750.0, 1.5) == pytest.approx(
        500.0, rel=0, abs=TOL
    )


def test_missing_timestamps_return_infinite_speed():
    """缺陷 4：缺少时间戳时必须视为无限速度，而不是零速度。"""
    assert math.isinf(travel_speed(None, None, 800.0, None))
    previous = _event("previous", 40.7128, -74.0060, None, "UTC-05:00")
    current = _event("current", 31.2304, 121.4737, None, "UTC+08:00")
    assert impossible_travel(previous, current, _policy()) is True


def test_speed_equal_to_limit_is_allowed():
    """缺陷 5：速度恰好等于阈值时应放行，不能判为异常。"""
    start = datetime(2026, 1, 1, 8, 0, tzinfo=UTC)
    previous = _event("previous", 0.0, 0.0, start)
    current = _event("current", 5.0, 0.0, start + timedelta(hours=1))
    km = haversine(
        (previous["lat"], previous["lon"]),
        (current["lat"], current["lon"]),
    )
    policy = _policy(max_speed_kmh=km)
    assert impossible_travel(previous, current, policy) is False


def test_trusted_region_requires_exact_cidr_match():
    """缺陷 6：CIDR 必须精确包含，不能用字符串前缀。"""
    regions = ["192.168.1.0/24"]
    assert trusted_region("192.168.1.77", regions) is True
    assert trusted_region("192.168.10.77", regions) is False


def test_timezone_shift_preserves_negative_offset():
    """缺陷 7：时区差要保留负值，并正确处理跨日线。"""
    assert timezone_shift("UTC+08:00", "UTC-05:00") == -13
    assert timezone_shift("UTC+14:00", "UTC-12:00") == -26


def test_step_up_aggregates_multiple_risks():
    """缺陷 8：多条低风险规则必须聚合成二次验证。"""
    policy = _policy(
        risk_weights={"new_device": 1, "unusual_time": 1},
        step_up_threshold=2,
    )
    combined = _event(
        "combined",
        31.2304,
        121.4737,
        datetime(2026, 1, 1, 9, 0, tzinfo=UTC),
        risks=("new_device", "unusual_time"),
    )
    single = _event(
        "single",
        31.2304,
        121.4737,
        datetime(2026, 1, 1, 9, 0, tzinfo=UTC),
        risks=("new_device",),
    )
    assert require_step_up(combined, policy) is True
    assert require_step_up(single, policy) is False


def test_validate_policy_flags_excessive_speed():
    """缺陷 9：策略校验必须检查速度阈值是否过高。"""
    policy = _policy(max_speed_kmh=9000.0)
    problems = validate_policy(policy)
    assert problems == ["速度阈值过高"]


def test_batch_does_not_reuse_stale_position():
    """缺陷 10：后一个事件不能复用更早事件的位置。"""
    new_york = datetime(
        2026, 1, 1, 8, 0, tzinfo=timezone(timedelta(hours=-5))
    )
    shanghai = datetime(
        2026, 1, 1, 22, 0, tzinfo=timezone(timedelta(hours=8))
    )
    events = [
        _event("a", 40.7128, -74.0060, new_york, "UTC-05:00"),
        _event("b", 31.2304, 121.4737, shanghai, "UTC+08:00"),
        _event(
            "c",
            31.2304,
            121.4737,
            shanghai + timedelta(hours=1),
            "UTC+08:00",
        ),
    ]
    result = fence_batch(events, _policy())
    assert result["impossible"] == [False, True, False]


def test_same_city_login_is_not_impossible():
    """额外：同城短时间登录不应触发。"""
    start = datetime(2026, 1, 1, 9, 0, tzinfo=UTC)
    previous = _event("a", 31.2304, 121.4737, start, "UTC+08:00")
    current = _event(
        "b",
        31.2304,
        121.4737,
        start + timedelta(minutes=30),
        "UTC+08:00",
    )
    assert impossible_travel(previous, current, _policy()) is False


def test_cross_continent_short_window_is_impossible():
    """额外：跨洲一小时内到达应触发。"""
    previous = _event(
        "a",
        40.7128,
        -74.0060,
        datetime(2026, 1, 1, 8, 0, tzinfo=timezone(timedelta(hours=-5))),
        "UTC-05:00",
    )
    current = _event(
        "b",
        31.2304,
        121.4737,
        datetime(2026, 1, 1, 22, 0, tzinfo=timezone(timedelta(hours=8))),
        "UTC+08:00",
    )
    assert impossible_travel(previous, current, _policy()) is True


def test_trusted_region_allows_forwarded_client_ip():
    """额外：代理头取最左侧客户端地址，且不信任右侧内网跳。"""
    regions = ["198.51.100.0/24", "10.0.0.0/8"]
    assert trusted_region("198.51.100.23, 10.0.0.9", regions) is True
    assert trusted_region("203.0.113.9, 10.0.0.9", regions) is False


def test_timezone_shift_across_date_line():
    """额外：跨日线时区差保持正确符号和数值。"""
    assert timezone_shift("UTC+13:00", "UTC-11:00") == -24
    assert timezone_shift("UTC-11:00", "UTC+13:00") == 24


def test_batch_matches_individual_evaluations():
    """额外：两批独立判定与逐个单独判定结果相同。"""
    new_york = datetime(
        2026, 1, 1, 8, 0, tzinfo=timezone(timedelta(hours=-5))
    )
    shanghai = datetime(
        2026, 1, 1, 22, 0, tzinfo=timezone(timedelta(hours=8))
    )
    events = [
        _event("a", 40.7128, -74.0060, new_york, "UTC-05:00"),
        _event("b", 31.2304, 121.4737, shanghai, "UTC+08:00"),
        _event(
            "c",
            31.2304,
            121.4737,
            shanghai + timedelta(hours=1),
            "UTC+08:00",
        ),
    ]
    policy = _policy()
    expected = [False, True, False]
    first_batch = fence_batch(events, policy)["impossible"]
    second_batch = fence_batch(events, policy)["impossible"]
    individual = [False] + [
        impossible_travel(events[index - 1], events[index], policy)
        for index in (1, 2)
    ]
    assert first_batch == expected
    assert second_batch == expected
    assert individual == expected