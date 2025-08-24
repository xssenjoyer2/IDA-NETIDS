#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import time
from pathlib import Path
import pandas as pd
import streamlit as st

ALERTS = Path("reports/scores/alerts_merged_stream.csv")
ACTIONS_LOG = Path("reports/logs/actions.log")

st.set_page_config(
    page_title="IDA-NETIDS Alerts",
    page_icon="🚨",
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.title("🚨 IDA-NETIDS — Live Alerts & Bans")

col1, col2, col3 = st.columns(3)
with col1:
    refresh = st.slider("Auto-refresh (sec)", 1, 10, 2)
with col2:
    min_sev = st.selectbox("Min severity", ["low", "med", "high"], index=1)
with col3:
    src_sel = st.multiselect("Sources", ["ml", "rules"], default=["ml", "rules"])

# Otomatik yenileme (sleep/rerun yerine)
st.autorefresh_interval = refresh * 1000

sev_rank = {"low": 0, "med": 1, "high": 2}

def load_alerts() -> pd.DataFrame:
    """alerts_merged_stream.csv dosyasını güvenle oku; boş/bozuk durumları tolere et."""
    if not ALERTS.exists() or ALERTS.stat().st_size == 0:
        return pd.DataFrame()

    try:
        df = pd.read_csv(ALERTS, low_memory=False)
    except pd.errors.EmptyDataError:
        # 0-byte veya henüz başlık yazılmadan açıldı
        return pd.DataFrame()
    except Exception as e:
        st.warning(f"Alerts okunamadı: {e}")
        return pd.DataFrame()

    # Normalize
    for c in ("severity", "source"):
        if c in df.columns:
            df[c] = df[c].astype(str).str.lower()

    # Filtreler
    if "severity" in df.columns:
        df = df[df["severity"].map(lambda x: sev_rank.get(x, 0)) >= sev_rank[min_sev]]
    if "source" in df.columns and src_sel:
        df = df[df["source"].isin([s.lower() for s in src_sel])]

    # Sıralama
    tcol = "ts_merged" if "ts_merged" in df.columns else ("ts_generated" if "ts_generated" in df.columns else "ts")
    if tcol in df.columns:
        df[tcol] = pd.to_numeric(df[tcol], errors="coerce").fillna(0.0)
        df = df.sort_values(tcol, ascending=False)

    return df

def load_ban_events():
    """actions.log’dan son ban olaylarını yakala (sessizce başarısız ol)."""
    if not ACTIONS_LOG.exists():
        return []
    try:
        lines = ACTIONS_LOG.read_text(errors="ignore").splitlines()
    except Exception:
        return []
    events = [ln for ln in lines[-400:] if "will ADD to ipset=" in ln or "ipset add" in ln]
    return events[-10:]

# Üstte ban bildirimleri (sondan başa)
ban_events = load_ban_events()
if ban_events:
    for ev in reversed(ban_events):
        st.error(ev)

st.subheader("Latest Alerts")
df = load_alerts()
if df.empty:
    st.info("No alerts yet.")
else:
    cols = [c for c in [
        "ts","ts_merged","source","type","severity","attacker_ip","target_ip",
        "proto","service","resp_p","margin","p_cal"
    ] if c in df.columns]
    st.dataframe(df[cols].head(500), use_container_width=True)

# Otomatik yenileme tetikleyici
time.sleep(refresh)
st.rerun()
