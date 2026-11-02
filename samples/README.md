# Controlled sample skills

Synthetic skills for demonstrating and testing AgentGuard. **They are inert outside the sandbox
workflow**: nothing here contacts a real host. Targets are the sandbox's own controlled sink or
reserved `.invalid` domains. Never copy them into an agent's real skills folder.

| Sample | Expected static result | Expected dynamic result |
|---|---|---|
| `benign-csv-stats` | no findings | no findings (verdict: no findings) |
| `runtime-env-dump` | MEDIUM `AG005` + hidden-content `AG006` | HIGH `DYN_ENV_EXPOSED` (prints honeypot env secrets) |
| `runtime-exfil-sink` | HIGH `AG001` | **CRITICAL `DYN_HONEYPOT_EXFIL`** (canary proven in sink traffic) |
| `runtime-exfil-evasive` | *evades regex rules* | **CRITICAL `DYN_HONEYPOT_EXFIL`** - static misses it, runtime proves it |
| `runtime-exfil-external` | HIGH `AG001` | HIGH `DYN_EXFIL_ATTEMPT` + `DYN_EGRESS_ATTEMPT` (blocked `.invalid` host) |

Scan one from the dashboard sample library, or:

```bash
python -m agentguard.cli scan samples/runtime-exfil-evasive --mode sandbox --output runs/evasive
```
