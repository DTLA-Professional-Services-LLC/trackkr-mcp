# Trackkr MCP Server — Smart Lockerless Parcel Management

A Model Context Protocol server that enables AI agents to autonomously manage incoming packages, log parcels, cross-reference unit directories, and track pick-up signatures without physical locker hardware.

- **Website:** [https://trackkr.app](https://trackkr.app)
- **Repository:** [https://github.com/DTLA-Professional-Services-LLC/trackkr-mcp](https://github.com/DTLA-Professional-Services-LLC/trackkr-mcp)
- **License:** MIT

---

## Capabilities / Tools List

- **`get_pending_parcels`**: Fetches the current ledger of uncollected packages, highlights aging stats (5+ days), and returns structured JSON context.
- **`log_incoming_parcel`**: Accepts parsed text from Google Cloud Vision OCR label scans, cross-references internal Firestore unit listings, and schedules automated email alerts via SendGrid.
- **`release_parcel_with_signature`**: Updates parcel state to `Picked Up`, records the timestamp, and securely saves the digital signature PNG layout to Firebase Storage.

---

## Configuration & Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `FIREBASE_CONFIG_JSON` | **Yes** | Path to your authorized Firebase service account credentials (or stringified JSON). |
| `USE_MOCK_OCR` | No | Set to `true` during local staging to bypass paid Google Cloud Vision API billing counters. |

---

## Quickstart Guide

### Run via `npx`

```bash
FIREBASE_CONFIG_JSON="./service-account.json" \
USE_MOCK_OCR="true" \
npx -y github:DTLA-Professional-Services-LLC/trackkr-mcp
```

### Add to `claude_desktop_config.json`

```json
{
  "mcpServers": {
    "trackkr-mcp": {
      "command": "npx",
      "args": ["-y", "github:DTLA-Professional-Services-LLC/trackkr-mcp"],
      "env": {
        "FIREBASE_CONFIG_JSON": "/path/to/service-account.json",
        "USE_MOCK_OCR": "true"
      }
    }
  }
}
```
