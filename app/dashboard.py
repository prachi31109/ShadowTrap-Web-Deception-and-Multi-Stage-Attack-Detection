# ShadowTrap - Defender Security Console
# Run:
#   python3 -m streamlit run app/dashboard.py

import json
import time
import html

import pandas as pd
import streamlit as st

try:
    from .db import get_conn
except ImportError:
    from db import get_conn


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="ShadowTrap SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)


# ============================================================
# GLOBAL STYLE
# ============================================================

st.html("""
<style>

.stApp {
    background: #f4f7fb;
}

.block-container {
    padding-top: 1.5rem;
    padding-bottom: 3rem;
    max-width: 1450px;
}

header[data-testid="stHeader"] {
    background: transparent;
}


/* =========================================================
   BRAND
   ========================================================= */

.brand-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 5px 0 20px 0;
}

.brand-left {
    display: flex;
    align-items: center;
    gap: 12px;
}

.brand-icon {
    width: 46px;
    height: 46px;
    border-radius: 12px;
    background: #2563eb;
    color: white;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 22px;
    font-weight: 800;
    box-shadow: 0 5px 15px rgba(37, 99, 235, 0.20);
}

.brand-title {
    font-size: 25px;
    font-weight: 800;
    color: #111827;
    line-height: 1.1;
}

.brand-subtitle {
    font-size: 12px;
    color: #6b7280;
    margin-top: 4px;
}

.live-pill {
    background: #ecfdf5;
    color: #059669;
    padding: 8px 13px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 750;
    border: 1px solid #bbf7d0;
}


/* =========================================================
   KPI CARDS
   ========================================================= */

.kpi {
    background: white;
    border: 1px solid #e5eaf1;
    border-radius: 14px;
    padding: 18px 20px;
    min-height: 112px;
    box-shadow: 0 5px 20px rgba(15, 23, 42, 0.04);
}

.kpi-label {
    color: #687386;
    font-size: 12px;
    font-weight: 650;
}

.kpi-value {
    color: #172033;
    font-size: 30px;
    font-weight: 800;
    margin-top: 7px;
}

.kpi-danger {
    color: #dc2626;
}


/* =========================================================
   SECTION
   ========================================================= */

.section-title {
    color: #172033;
    font-size: 18px;
    font-weight: 800;
    margin: 25px 0 12px;
}


/* =========================================================
   ATTACK CARD
   ========================================================= */

.attack-card {
    background: white;
    border: 1px solid #e5eaf1;
    border-radius: 15px;
    padding: 22px;
    margin-bottom: 16px;
    box-shadow: 0 5px 20px rgba(15, 23, 42, 0.04);
}

.attack-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.attack-id {
    font-size: 15px;
    font-weight: 800;
    color: #172033;
}

.high-badge {
    background: #fef2f2;
    color: #dc2626;
    padding: 6px 10px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 800;
    border: 1px solid #fecaca;
}

.medium-badge {
    background: #fffbeb;
    color: #d97706;
    padding: 6px 10px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 800;
    border: 1px solid #fde68a;
}


/* =========================================================
   PIPELINE
   ========================================================= */

.pipeline {
    display: flex;
    align-items: center;
    gap: 0;
    margin: 22px 0;
    overflow-x: auto;
    padding-bottom: 5px;
}

.stage {
    display: flex;
    align-items: center;
    white-space: nowrap;
}

.stage-box {
    background: #eff6ff;
    color: #1d4ed8;
    border: 1px solid #bfdbfe;
    border-radius: 10px;
    padding: 10px 13px;
    font-size: 12px;
    font-weight: 750;
}

.stage-arrow {
    color: #94a3b8;
    margin: 0 8px;
    font-size: 16px;
}


/* =========================================================
   EVIDENCE
   ========================================================= */

.evidence {
    background: #f8fafc;
    border: 1px solid #edf1f5;
    border-radius: 11px;
    padding: 15px;
    margin-top: 10px;
}

.evidence-title {
    font-size: 12px;
    font-weight: 800;
    color: #172033;
    margin-bottom: 9px;
}

.evidence-item {
    color: #687386;
    font-size: 12px;
    margin: 6px 0;
}


/* =========================================================
   EMPTY STATE
   ========================================================= */

.empty-state {
    background: white;
    border: 1px dashed #cbd5e1;
    border-radius: 14px;
    text-align: center;
    padding: 45px 20px;
    color: #687386;
}

.empty-icon {
    font-size: 35px;
    margin-bottom: 10px;
}


/* =========================================================
   FOOTER
   ========================================================= */

.footer {
    margin-top: 35px;
    padding-top: 18px;
    border-top: 1px solid #e5eaf1;
    color: #8791a2;
    font-size: 11px;
    text-align: center;
}

</style>
""")


# ============================================================
# DATABASE
# ============================================================

conn = get_conn()


total_events = conn.execute(
    "SELECT COUNT(*) c FROM events"
).fetchone()["c"]


total_sequences = conn.execute(
    "SELECT COUNT(*) c FROM sequences"
).fetchone()["c"]


high_sequences = conn.execute(
    "SELECT COUNT(*) c FROM sequences WHERE confidence='HIGH'"
).fetchone()["c"]


sources = conn.execute(
    "SELECT COUNT(DISTINCT ip) c FROM events"
).fetchone()["c"]


events = pd.read_sql_query(
    """
    SELECT
        ts,
        ip,
        sid,
        method,
        path,
        event_type,
        detail
    FROM events
    ORDER BY id DESC
    LIMIT 30
    """,
    conn,
)


sequences = pd.read_sql_query(
    """
    SELECT *
    FROM sequences
    ORDER BY id DESC
    LIMIT 10
    """,
    conn,
)


conn.close()


# ============================================================
# HEADER
# ============================================================

st.html("""
<div class="brand-row">

    <div class="brand-left">

        <div class="brand-icon">🛡️</div>

        <div>
            <div class="brand-title">
                ShadowTrap
            </div>

            <div class="brand-subtitle">
                Stealth Deception &amp; Attack Intelligence Platform
            </div>
        </div>

    </div>

    <div class="live-pill">
        ● LIVE MONITORING
    </div>

</div>
""")


# ============================================================
# KPI CARDS
# ============================================================

c1, c2, c3, c4 = st.columns(4)


with c1:
    st.html(f"""
    <div class="kpi">
        <div class="kpi-label">
            LOGGED EVENTS
        </div>

        <div class="kpi-value">
            {total_events}
        </div>
    </div>
    """)


with c2:
    st.html(f"""
    <div class="kpi">
        <div class="kpi-label">
            ATTACK SEQUENCES
        </div>

        <div class="kpi-value">
            {total_sequences}
        </div>
    </div>
    """)


with c3:
    st.html(f"""
    <div class="kpi">
        <div class="kpi-label">
            HIGH CONFIDENCE
        </div>

        <div class="kpi-value kpi-danger">
            {high_sequences}
        </div>
    </div>
    """)


with c4:
    st.html(f"""
    <div class="kpi">
        <div class="kpi-label">
            OBSERVED SOURCES
        </div>

        <div class="kpi-value">
            {sources}
        </div>
    </div>
    """)


# ============================================================
# ATTACK SEQUENCES
# ============================================================

st.html("""
<div class="section-title">
    🚨 Reconstructed Attack Sequences
</div>
""")


if sequences.empty:

    st.html("""
    <div class="empty-state">

        <div class="empty-icon">
            🛡️
        </div>

        <strong>
            No multi-stage attack detected
        </strong>

        <br><br>

        <span>
            The system is monitoring deceptive resources.
            Run the synthetic attacker simulator to generate
            a controlled test sequence.
        </span>

    </div>
    """)

else:

    for _, row in sequences.iterrows():

        try:
            stages = json.loads(row["stage_json"])
        except Exception:
            stages = []

        try:
            reasons = json.loads(row["reasons_json"])
        except Exception:
            reasons = []

        confidence = str(row["confidence"])

        if confidence == "HIGH":
            badge_class = "high-badge"
        else:
            badge_class = "medium-badge"


        sequence_id = html.escape(str(row["id"]))
        source_ip = html.escape(str(row["ip"]))
        session_id = html.escape(str(row["sid"]))
        n_events = html.escape(str(row["n_events"]))


        # ----------------------------------------------------
        # Attack header
        # ----------------------------------------------------

        st.html(f"""
        <div class="attack-card">

            <div class="attack-header">

                <div class="attack-id">
                    Sequence #{sequence_id}
                </div>

                <div class="{badge_class}">
                    {html.escape(confidence)} CONFIDENCE
                </div>

            </div>

            <div style="
                margin-top:8px;
                color:#687386;
                font-size:12px;
            ">

                Source:
                <b>{source_ip}</b>

                &nbsp; · &nbsp;

                Session:
                <b>{session_id}</b>

                &nbsp; · &nbsp;

                Events:
                <b>{n_events}</b>

            </div>

        </div>
        """)


        # ----------------------------------------------------
        # Pipeline
        # ----------------------------------------------------

        pipeline_parts = [
            '<div class="pipeline">'
        ]


        for i, stage in enumerate(stages):

            stage_name = html.escape(
                str(stage.get("name", "Unknown Stage"))
            )

            pipeline_parts.append(
                f"""
                <div class="stage">
                    <div class="stage-box">
                        {stage_name}
                    </div>
                </div>
                """
            )

            if i < len(stages) - 1:
                pipeline_parts.append(
                    """
                    <div class="stage-arrow">
                        →
                    </div>
                    """
                )


        pipeline_parts.append("</div>")

        st.html("".join(pipeline_parts))


        # ----------------------------------------------------
        # Timeline + evidence
        # ----------------------------------------------------

        left, right = st.columns(2)


        with left:

            st.markdown("**Attack Timeline**")


            timeline_parts = []

            for stage in stages:

                stage_ts = html.escape(
                    str(stage.get("ts", ""))
                )

                stage_number = html.escape(
                    str(stage.get("stage", ""))
                )

                stage_name = html.escape(
                    str(stage.get("name", ""))
                )

                timeline_parts.append(
                    f"""
                    <div style="
                        padding:10px 0;
                        border-bottom:1px solid #edf1f5;
                        font-size:12px;
                    ">

                        <span style="
                            color:#94a3b8;
                        ">
                            {stage_ts}
                        </span>

                        &nbsp;&nbsp;

                        <b>
                            Stage {stage_number}
                        </b>

                        &nbsp;·&nbsp;

                        {stage_name}

                    </div>
                    """
                )


            if timeline_parts:
                st.html("".join(timeline_parts))
            else:
                st.info("No stage timeline available.")


        with right:

            st.markdown("**Why is this suspicious?**")


            reason_parts = [
                '<div class="evidence">'
            ]


            if reasons:

                for reason in reasons:

                    safe_reason = html.escape(
                        str(reason)
                    )

                    reason_parts.append(
                        f"""
                        <div class="evidence-item">
                            ✓ {safe_reason}
                        </div>
                        """
                    )

            else:

                reason_parts.append(
                    """
                    <div class="evidence-item">
                        No explanation available.
                    </div>
                    """
                )


            reason_parts.append("</div>")

            st.html("".join(reason_parts))


# ============================================================
# LIVE EVENTS
# ============================================================

st.html("""
<div class="section-title">
    📡 Recent Deceptive-Resource Events
</div>
""")


if events.empty:

    st.info(
        "No deceptive-resource interactions recorded yet."
    )

else:

    display_events = events.copy()


    display_events["event_type"] = (
        display_events["event_type"]
        .astype(str)
        .str.replace("_", " ", regex=False)
        .str.title()
    )


    display_events = display_events.rename(
        columns={
            "ts": "Time",
            "ip": "Source IP",
            "sid": "Session",
            "method": "Method",
            "path": "Path",
            "event_type": "Event",
            "detail": "Details",
        }
    )


    st.dataframe(
        display_events,
        width="stretch",
        hide_index=True,
    )


# ============================================================
# FOOTER
# ============================================================

st.html("""
<div class="footer">

    ShadowTrap · Defensive security research prototype ·
    Synthetic/local laboratory environment

</div>
""")


# ============================================================
# AUTO REFRESH
# ============================================================

time.sleep(2)
st.rerun()