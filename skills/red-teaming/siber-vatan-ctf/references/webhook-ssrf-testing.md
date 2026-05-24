# Webhook / SSRF Testing Patterns

## Finding Webhook Endpoints
- Look for "Webhook Tester", "URL Tester", "Send Request" functionality in dashboards
- Common API paths: `/api/webhook/test`, `/api/webhook/scan`, `/api/proxy`
- Hidden inputs/buttons that submit URLs
- User-controllable callback/notification URLs

## SSRF Testing Strategy
1. **Test connectivity**: Send requests to public servers you control (webhook.site, requestbin)
2. **Internal probing**:
   - `http://localhost/` — basic localhost
   - `http://127.0.0.1:{port}/` — various ports (80, 443, 3000, 5000, 8080, 1337)
   - `http://[::1]/` — IPv6 localhost
3. **Cloud metadata**:
   - AWS: `http://169.254.169.254/latest/meta-data/`
   - GCP: `http://metadata.google.internal/computeMetadata/v1/`
   - Azure: `http://169.254.169.254/metadata/instance?api-version=2021-02-01`
4. **Protocol smuggling**:
   - `file:///etc/passwd` — if the fetcher supports file://
   - `gopher://internal-service:6379/_...` — SSRF to Redis
   - `dict://internal-service:6379/info` — dict protocol

## Interpreting Responses
- `502 Bad Gateway` — connection refused (port closed)
- `5xx timeout` — host unreachable or firewall blocked
- `200 OK` + response body — service reached!
- Error messages often leak internal IPs, hostnames, or stack traces

## Hooking for Callbacks
When you control a server, watch for:
- Inbound HTTP requests from the target IP
- DNS lookups (can indicate blind SSRF)
- Delayed callbacks (time-based detection)