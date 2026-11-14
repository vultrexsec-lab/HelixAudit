# HelixAudit custom Nuclei templates

Put custom YAML templates under `nuclei-templates/` (this tree is passed to nuclei with `-t`).

## Layout
```
nuclei-templates/
  helixaudit/          # bundled HelixAudit templates
  custom/              # your org templates (create this folder)
```

## Scan / env controls
| Variable / config | Meaning | Default |
|-------------------|---------|---------|
| `NUCLEI_SEVERITY` | severities to include | `critical,high,medium` |
| `NUCLEI_TAGS` | only these tags (comma) | empty = all |
| `NUCLEI_EXCLUDE_TAGS` | exclude tags | `dos,fuzz` |
| `NUCLEI_TEMPLATE_PATH` | extra template dir | `backend/nuclei-templates` |
| `NUCLEI_USE_DEFAULT` | also use nuclei default templates | `true` |
| `NUCLEI_RATE_LIMIT` | requests/sec | `40` |
| `NUCLEI_TIMEOUT` | per-request seconds | `5` |

Per-scan JSON `config` may override:
```json
{
  "nuclei_severity": "critical,high",
  "nuclei_tags": "helixaudit,cve",
  "nuclei_exclude_tags": "dos,fuzz,intrusive",
  "nuclei_use_default": true
}
```

## Authoring tips
- Always avoid matching bare HTML soft-404s when checking file exposure.
- Prefer `word` / `regex` content matchers over status-only.
- Tag with `helixaudit` so runs can filter `-tags helixaudit`.
