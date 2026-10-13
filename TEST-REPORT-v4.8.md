# ariaatashin 4.8.0 — validation report

Date: 2026-10-12. Updated from the confirmed complete 4.7 archive. No production deployment, Telegram send, commercial game login or Iranian ISP test was performed.

## Verified

| Check | Result |
|---|---|
| Go unit/regression suite, race detector | PASS, launcher 9.407 s; companion 1.036 s |
| Full integration/regression suite, race detector | PASS, launcher 32.347 s; companion 1.043 s; contract package 1.101 s |
| go vet, complete panel build, JavaScript syntax | PASS |
| Windows amd64, Linux amd64/arm64, macOS amd64/arm64 companions | Built; SHA256 manifest matches all five binaries |
| Native direct and VLESS/WS proxy HTTPS tests | PASS; valid fixture TLS on both paths |
| Independent proxy test while game selector is direct | PASS; breaking only the VLESS exit breaks only the proxy test |
| Native Clash API selector PUT and GET verification | PASS for direct and game-route |
| Actual companion executable, probe-only mode | PASS; writes private report, selects direct for healthy fixtures, reports applied=false |
| Actual companion → native VLESS proxy → HTTPS panel report API | PASS; scoped result persisted by panel |
| Native TUN output schema | PASS for full, domain and Windows process modes |
| Panel browser story | PASS; downloads the private Rainbow kit and displays the recomputed device result |
| Desktop and 390px mobile panel | PASS; zero JavaScript errors and no horizontal overflow |
| Local companion dashboard with real engine/controller | PASS; actual selector change, reporting, refresh retains local authorization |
| Probe-only local dashboard | PASS; gameplay confirmation is disabled without active TUN |
| Local companion dashboard at 390px | PASS; no JavaScript errors or horizontal overflow |

The native runtime uses the pinned source with the existing optional-monitor and stats-alias compatibility patches, built with Clash API support. The official 1.14.3 engine accepted the TUN schemas; its optional network monitor cannot start in this container because netlink is restricted. The compatibility build runs the HTTPS/VLESS/controller tests without TUN. Explicit interface detection remains required for actual TUN; no sandbox escalation was used.

## Decision and reporting

- Two successful rounds per target are required for a healthy service path. Mixed results, 401, 429 and server errors remain inconclusive. Off-scope redirects are not followed or interpreted as a ban. TLS verification is retained.
- Explicit failed gameplay on both paths cannot be overridden by a healthy publisher website. User-confirmed gameplay is labeled separately from HTTPS service measurements.
- Periodic checks keep the selected gameplay path locked; an explicit pre-game retest can apply a new initial service selection. Real controller selection is read back. A dead or different selector is not reported as an applied tunnel.
- Wrong tokens, replayed sequence numbers, unexpected targets, inactive accounts and revoked jobs are rejected. The server recomputes the decision rather than trusting a client-supplied label.
- Only token hashes persist. Public job listing redacts hashes/tokens. Private state is 0600. Creating a kit does not change the shared DNS account's direct-game policy.
- Local API requires a loopback Host, local bearer secret and matching Origin. Foreign Host/Origin and missing authorization fail. Mobile kit requests fail clearly rather than producing an incompatible executable.

## Browser stories

Panel: admin/admin login → DNS settings and persisted direct COD Mobile policy → native connection user → game catalog → owned exit import → standard Battlefield and Android Clash exports → Rainbow Six private Windows kit → controlled device report → server recomputation and service-only label → mobile view and in-panel guide. Measurements injected for this browser display check are controlled fixtures, not real game outcomes.

Companion: controlled HTTPS target and independent HTTP proxy → native sing-box → real companion executable → local browser page → real selector change → refresh with retained session-only authorization → disabled gameplay confirmation in probe-only mode → mobile layout. The HTTP fixture is separate from the native Xray/VLESS report test; both paths are covered.

## Practical limits

Publisher-service responses do not prove account-region acceptance, login API access, NAT type or UDP match success. Commercial game sessions require testing on the customer's installed game and network. Gameplay confirmation is entered by the user; it is not fabricated by the software. No universal sanctions classification, unblock guarantee or game-ping claim is made.

Windows/macOS/ARM binaries were cross-compiled but were not executed on those physical devices. Linux execution, controller and reporting were tested without creating an OS TUN in this environment. Actual privileged TUN data paths, console sharing, Iranian operators and national connectivity outages remain device/network checks. The current companion is for desktop; no Android APK or iOS application is included. Standard mobile exports remain available.

Docker daemon was unavailable, so the complete image was not built here. Dockerfile builds the companion before embedding assets and enables Clash API in the pinned engine; the corresponding Go builds and native configuration checks were exercised.

## Reproduction

```sh
sh scripts/build-game-agent.sh
go test -race ./...
go vet ./...
go build -buildvcs=false .
ARIA_TEST_ENGINE_DIR=/path/to/pinned/x-ui \
ARIA_TEST_SING_BOX=/path/to/compatibility/sing-box-with-clash \
ARIA_TEST_SING_BOX_CLASH=/path/to/compatibility/sing-box-with-clash \
ARIA_TEST_WS_MODULE=/path/to/node_modules/ws \
ARIA_TEST_DENO=/path/to/deno \
go test -race -tags=integration -count=1 ./...
ARIA_TEST_SING_BOX=/path/to/compatibility/sing-box-with-clash \
ARIA_TEST_CHROMIUM=/path/to/chromium \
node scripts/qa-game-agent.cjs
```

Playwright is required for the final browser command. Validation screenshots and private TLS fixtures are excluded from the distributable.
