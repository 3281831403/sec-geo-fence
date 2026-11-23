"""Geographic fence primitives for impossible-travel risk checks.

All inputs are injected by the caller. The module is offline, uses only
the standard library, and intentionally contains exactly eight stubs.
Coordinates are latitude/longitude pairs in decimal degrees. Numeric
results are expected to match with an absolute tolerance of 1e-9 unless
a function states otherwise.
"""

from datetime import datetime
import ipaddress
import math


def haversine(a: tuple[float, float], b: tuple[float, float]) -> float:
    """Return the great-circle distance between two points in kilometres.

    Each argument is a (latitude, longitude) pair in decimal degrees.
    The calculation uses the haversine formula on a sphere with mean
    radius 6371.0088 km. The result is non-negative. Tests compare it
    with an absolute tolerance of 1e-9 km; a planar approximation or a
    missing degree-to-radian conversion must fail those tests.
    """
    raise NotImplementedError("haversine is a stub")


def travel_speed(
    prev: datetime | None,
    cur: datetime | None,
    km: float,
    hours: float | None,
) -> float:
    """Return displacement speed in kilometres per hour.

    prev and cur are optional timezone-aware datetimes. When hours is not
    None it is an explicitly injected elapsed duration and takes
    precedence. Otherwise elapsed hours are computed from cur - prev.
    When neither a duration nor both timestamps are available, return
    math.inf. A non-positive duration with positive distance also returns
    math.inf, while zero distance over zero duration returns 0.0.
    Negative distance raises ValueError. Finite results are compared with
    an absolute tolerance of 1e-9 km/h.
    """
    raise NotImplementedError("travel_speed is a stub")


def impossible_travel(prev: dict, cur: dict, policy: dict) -> bool:
    """Return whether travel between two events exceeds the speed policy.

    Each event supplies lat, lon and an optional ts. Distance comes from
    haversine and speed from travel_speed using the event timestamps.
    Missing timestamps therefore produce infinite speed and count as
    impossible travel. The comparison is strict: a speed exactly equal to
    policy max_speed_kmh is allowed, with an absolute tolerance of
    1e-9 km/h.
    """
    raise NotImplementedError("impossible_travel is a stub")


def trusted_region(ip: str, regions: list[str]) -> bool:
    """Return whether a source address belongs to a trusted CIDR region.

    ip is either one address or an X-Forwarded-For style comma-separated
    chain. Only the left-most entry, the original client, is checked.
    regions is an iterable of CIDR strings. Containment must be exact at
    the network level rather than a string-prefix comparison. Malformed
    addresses or networks, and an empty region list, return False.
    """
    raise NotImplementedError("trusted_region is a stub")


def timezone_shift(prev_tz: str, cur_tz: str) -> int:
    """Return the signed whole-hour offset from prev_tz to cur_tz.

    Inputs are fixed UTC offsets such as UTC+08:00, UTC-05:00 or Z, using
    whole-hour offsets only. The result is the current offset minus the
    previous offset and may be negative, zero, or larger than 12 when the
    date line is crossed. Negative values must not be clamped to zero.
    """
    raise NotImplementedError("timezone_shift is a stub")


def require_step_up(event: dict, policy: dict) -> bool:
    """Return whether an event's aggregate risk requires a second factor.

    event risks is an iterable of risk tags. policy risk_weights maps tags
    to non-negative numeric weights, and policy step_up_threshold is the
    trigger value. Sum the weights of active tags, treating unknown tags
    as zero, and trigger when the total is greater than or equal to the
    threshold. Missing or unusable step-up configuration fails closed and
    returns True.
    """
    raise NotImplementedError("require_step_up is a stub")


def validate_policy(policy: dict) -> list[str]:
    """Return policy problems in a fixed order.

    Checks, in order: max_speed_kmh is a number greater than zero and at
    most 1000; regions is a non-empty whitelist; risk_weights is non-empty
    with positive weights and step_up_threshold is positive. Return the
    exact messages 速度阈值过高, 缺少地区白名单 and 缺少二次验证 for the
    corresponding problems, or an empty list for a valid policy.
    """
    raise NotImplementedError("validate_policy is a stub")


def fence_batch(events: list[dict], policy: dict) -> dict:
    """Return impossible-travel flags for a chronological event batch.

    The result is a dict with an impossible key holding a list of booleans
    aligned with events. The first event has no predecessor and is False.
    Each later event is compared only with the immediately preceding event
    in the same batch through impossible_travel. No position or result may
    be reused across positions or calls. An empty batch returns an empty
    list. Missing timestamps count as impossible travel.
    """
    raise NotImplementedError("fence_batch is a stub")