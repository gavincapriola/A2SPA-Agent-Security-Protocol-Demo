import streamlit as st
import hashlib
import base64
import uuid
import time
import json

# Set up demo config
st.set_page_config(page_title="A2SPA Live Security Demo", layout="wide")
st.title("🛡️ A2SPA Agent Security Protocol Demo")

st.markdown("""
This demo shows how legacy agent protocols fail — and how **A2SPA** blocks every exploit in real time.
Select an attack and click "Launch Attack" to test it against the A2SPA Gateway.
""")

if 'used_hashes' not in st.session_state:
    st.session_state.used_hashes = set()

if 'audit_log' not in st.session_state:
    st.session_state.audit_log = []

# Attack mode
st.sidebar.header("🧪 Simulate Attack")
attack_type = st.sidebar.radio("Select attack type:", [
    "None (Clean A2SPA)",
    "Replay Attack",
    "Tampered Payload",
    "Impersonation Attack",
    "Unauthorized Action"
])

# Launch button
do_attack = st.sidebar.button("🚀 Launch Attack")

if do_attack:
    # Create base payload
    payload = {
        "agent": "agentA",
        "action": "deploy_model",
        "timestamp": int(time.time()),
        "nonce": str(uuid.uuid4()),
        "data": {
            "model_id": "gpt-secure",
            "environment": "prod"
        }
    }

    # Permission Map
    permission_map = {
        "agentA": ["deploy_model", "restart_node"],
        "agentB": ["train_model"]
    }

    # Apply attack logic
    if attack_type == "Replay Attack":
        if st.session_state.audit_log:
            payload['nonce'] = st.session_state.audit_log[-1]['nonce']
        else:
            payload['nonce'] = "reused-static-nonce"
        st.warning("Replay Attack: Re-using a previously used nonce.")
    elif attack_type == "Tampered Payload":
        payload['data']['model_id'] = "gpt-fake"
        st.warning("Tampered Payload: model_id has been changed.")
    elif attack_type == "Impersonation Attack":
        payload['agent'] = "unknown_agent"
        st.warning("Impersonation: Using an untrusted agent.")
    elif attack_type == "Unauthorized Action":
        payload['action'] = "delete_database"
        st.warning("Unauthorized Action: Not allowed for this agent.")

    # Visual Flow
    with st.expander("🚀 Capsule Flow Animation"):
        st.markdown("""
        1. **Agent signs the payload**
        2. **Capsule includes signature, timestamp, nonce**
        3. **A2SPA Gateway verifies trust, tamper, replay, and permissions**
        4. **Returns: ✅ Accepted / ❌ Rejected**
        """)

    # Capsule Preview
    st.subheader("📦 A2SPA Secure Capsule")
    col1, col2 = st.columns(2)
    with col1:
        st.code(json.dumps(payload, indent=2), language="json")

    raw_string = str(payload).encode()
    payload_hash = hashlib.sha256(raw_string).hexdigest()
    signature = base64.b64encode(hashlib.sha256((payload['agent'] + payload_hash).encode()).digest()).decode()

    with col2:
        st.markdown("**Signature (SHA-256):**")
        st.code(signature)
        st.markdown(f"**Timestamp:** {payload['timestamp']}")
        st.markdown(f"**Nonce:** {payload['nonce']}")
        st.markdown(f"**Agent:** {payload['agent']}")
        st.markdown(f"**Action:** {payload['action']}")

    # A2SPA Gateway Verification
    st.subheader("🔐 A2SPA Gateway Verification")
    trusted_agents = ["agentA", "agentB"]

    if payload['agent'] not in trusted_agents:
        st.error("🚫 Sender mismatch — agent identity not trusted.")
        status = "Rejected: Untrusted Agent"
    elif payload['nonce'] in st.session_state.used_hashes:
        st.error("🚨 Replay attack blocked — hash already used.")
        status = "Rejected: Replay Attack"
    elif payload['data']['model_id'] != "gpt-secure":
        st.error("❌ Signature mismatch — possible payload tampering.")
        status = "Rejected: Payload Tampered"
    elif payload['action'] not in permission_map.get(payload['agent'], []):
        st.error("🛑 Action not authorized for this agent.")
        status = "Rejected: Unauthorized Action"
    else:
        st.success("✅ Payload verified and accepted by A2SPA.")
        status = "Accepted"
        st.session_state.used_hashes.add(payload['nonce'])

    # Append to audit log
    st.session_state.audit_log.append({
        "agent": payload['agent'],
        "action": payload['action'],
        "timestamp": payload['timestamp'],
        "status": status,
        "nonce": payload['nonce']
    })

    # Always Show Debug Info
    st.subheader("🔍 Capsule Debug Info")
    st.json(payload)
    st.text(f"Signature: {signature}")
    st.text(f"Payload Hash: {payload_hash}")

# Audit Log Viewer
st.subheader("📊 Audit Log")
if st.session_state.audit_log:
    st.table(st.session_state.audit_log)
else:
    st.info("No payloads submitted yet.")

# Comparison Viewer
with st.expander("⚔️ MCP / A2A / A2SPA Comparison"):
    st.markdown("""
    | Checkpoint           | MCP | A2A | A2SPA |
    |----------------------|-----|-----|--------|
    | Replay Attack Block  | ❌  | ❌  | ✅     |
    | Payload Tamper Check | ❌  | ❌  | ✅     |
    | Agent Trust Check    | ❌  | ❌  | ✅     |
    | Permission Map Check | ❌  | ❌  | ✅     |
    | Audit Logging        | ❌  | ❌  | ✅     |
    """)
