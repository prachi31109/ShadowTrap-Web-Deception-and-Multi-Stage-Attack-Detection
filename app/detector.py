# ShadowTrap - Detection & Correlation Engine
# The "Attack Story Engine"

import json
from datetime import datetime

try:
    from .db import get_conn
except ImportError:
    from db import get_conn


# ============================================================
# EVENT TYPE -> ATTACK STAGE
# ============================================================

STAGE_MAP = {
    "hidden_route": 1,
    "credential_probe": 2,
    "panel_access": 2,
    "honeytoken": 3,
    "decoy_file": 4,
}


# ============================================================
# ATTACK STAGE NAMES
# ============================================================

STAGE_NAMES = {
    1: "Reconnaissance",
    2: "Credential Probing",
    3: "Honeytoken Interaction",
    4: "Sensitive Resource Probing",
}


# ============================================================
# EXPLAINABILITY REASONS
# ============================================================

REASONS = {
    1: (
        "Hidden endpoint accessed that is not linked "
        "from the public site"
    ),

    2: (
        "Credentials were submitted to a phantom "
        "(non-existent) admin login"
    ),

    3: (
        "A decoy API key (honeytoken) was used - "
        "legitimate users never use it"
    ),

    4: (
        "A decoy sensitive file was requested"
    ),
}


GENERAL_REASON = (
    "Multiple deceptive resources were accessed from the "
    "same session/source, indicating a probable multi-stage attack."
)


# ============================================================
# EVENT LOGGING
# ============================================================

def log_event(
    ip,
    sid,
    method,
    path,
    event_type,
    detail="",
    ua=""
):
    """
    Store an event and immediately attempt to correlate
    the session into an attack sequence.
    """

    conn = get_conn()

    ts = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    conn.execute(
        """
        INSERT INTO events(
            ts,
            ip,
            sid,
            method,
            path,
            event_type,
            detail,
            ua
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            ts,
            ip,
            sid,
            method,
            path,
            event_type,
            detail,
            ua,
        ),
    )

    conn.commit()

    sequence = correlate(conn, sid)

    conn.close()

    return sequence


# ============================================================
# ATTACK CORRELATION ENGINE
# ============================================================

def correlate(conn, sid):
    """
    Reconstruct an attack story from events belonging
    to the same session.

    Confidence rules:

    HIGH:
        All four deception stages observed in the same
        session:
            1. Reconnaissance
            2. Credential Probing
            3. Honeytoken Interaction
            4. Sensitive Resource Probing

    MEDIUM:
        At least three different attack stages observed.

    LOW:
        Two different stages observed.

    A single event is not enough to create a sequence.
    """

    # --------------------------------------------------------
    # Get all events for this session
    # --------------------------------------------------------

    rows = conn.execute(
        """
        SELECT *
        FROM events
        WHERE sid=?
        ORDER BY id
        """,
        (sid,),
    ).fetchall()


    if not rows:
        return None


    # --------------------------------------------------------
    # Record the first timestamp for each observed stage
    # --------------------------------------------------------

    first_ts = {}

    for row in rows:

        stage = STAGE_MAP.get(
            row["event_type"]
        )

        if stage and stage not in first_ts:
            first_ts[stage] = row["ts"]


    # --------------------------------------------------------
    # Need at least two different stages
    # before creating an attack sequence
    # --------------------------------------------------------

    if len(first_ts) < 2:
        return None


    # --------------------------------------------------------
    # Sort stages in attack progression order
    # --------------------------------------------------------

    stages = sorted(first_ts.keys())


    # --------------------------------------------------------
    # Confidence calculation
    # --------------------------------------------------------

    if len(stages) >= 4:

        confidence = "HIGH"

    elif len(stages) >= 3:

        confidence = "MEDIUM"

    else:

        confidence = "LOW"


    # --------------------------------------------------------
    # Build stage information for dashboard
    # --------------------------------------------------------

    stage_list = []

    for stage in stages:

        stage_list.append(
            {
                "stage": stage,
                "name": STAGE_NAMES[stage],
                "ts": first_ts[stage],
            }
        )


    # --------------------------------------------------------
    # Build explainable reasons
    # --------------------------------------------------------

    reasons = []

    for stage in stages:

        reasons.append(
            REASONS[stage]
        )


    # Add correlation explanation when
    # multiple deceptive stages are observed.

    if len(stages) >= 2:

        reasons.append(
            GENERAL_REASON
        )


    # --------------------------------------------------------
    # Sequence time range
    # --------------------------------------------------------

    start_ts = rows[0]["ts"]
    end_ts = rows[-1]["ts"]

    n_events = len(rows)


    # --------------------------------------------------------
    # Check whether this session already has
    # a sequence in the database
    # --------------------------------------------------------

    existing = conn.execute(
        """
        SELECT id
        FROM sequences
        WHERE sid=?
        """,
        (sid,),
    ).fetchone()


    # ========================================================
    # UPDATE EXISTING SEQUENCE
    # ========================================================

    if existing:

        conn.execute(
            """
            UPDATE sequences
            SET
                start_ts=?,
                end_ts=?,
                stage_json=?,
                confidence=?,
                reasons_json=?,
                n_events=?
            WHERE sid=?
            """,
            (
                start_ts,
                end_ts,
                json.dumps(stage_list),
                confidence,
                json.dumps(reasons),
                n_events,
                sid,
            ),
        )

        seq_id = existing["id"]


    # ========================================================
    # CREATE NEW SEQUENCE
    # ========================================================

    else:

        cursor = conn.execute(
            """
            INSERT INTO sequences(
                ip,
                sid,
                start_ts,
                end_ts,
                stage_json,
                confidence,
                reasons_json,
                n_events
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                rows[0]["ip"],
                sid,
                start_ts,
                end_ts,
                json.dumps(stage_list),
                confidence,
                json.dumps(reasons),
                n_events,
            ),
        )

        seq_id = cursor.lastrowid


    # --------------------------------------------------------
    # Commit correlation result
    # --------------------------------------------------------

    conn.commit()


    # --------------------------------------------------------
    # Return structured result
    # --------------------------------------------------------

    return {
        "id": seq_id,
        "stages": stage_list,
        "confidence": confidence,
        "reasons": reasons,
    }