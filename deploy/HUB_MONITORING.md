# Hub self-monitoring (HANDOFF-FLEET.md §8.2)

The fleet view (§5) reports on sites. Nothing reports on the hub — when
the EC2 instance the hub runs on goes down, the fleet view goes down
with it, so the failure would otherwise surface days later as a
CRL-expiry outage at every site simultaneously, the exact fail-closed
scenario this whole system exists to avoid.

Two independent signals, neither routed through the app's own Slack
webhook (`ALERT_WEBHOOK_URL`) — if the hub is down, it can't tell you
that over its own path.

## 1. EC2 instance status alarm

Standard AWS status-check alarm, no app changes needed:

```bash
aws cloudwatch put-metric-alarm \
  --alarm-name certmanager-hub-instance-status \
  --namespace AWS/EC2 \
  --metric-name StatusCheckFailed \
  --dimensions Name=InstanceId,Value=<INSTANCE_ID> \
  --statistic Maximum \
  --period 60 \
  --evaluation-periods 3 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --alarm-actions <SNS_TOPIC_ARN_NOT_SLACK>
```

`SNS_TOPIC_ARN_NOT_SLACK` should notify somewhere that doesn't depend on
this app or its webhook — email, PagerDuty, a second Slack workspace via
its own AWS Chatbot integration, whatever isn't "the thing that just
went down."

## 2. Heartbeat-absence alarm (app-level, not just the instance)

An instance can be `running` while the app itself is wedged (DB lock,
crashed worker, disk full). `scripts/fleet_watch.py` sends a heartbeat
on every successful run — set `HEARTBEAT_URL` in `.env` to a
dead-man's-switch endpoint (a [healthchecks.io](https://healthchecks.io)
check, or a Lambda that calls `PutMetricData` on a ping and a
CloudWatch alarm on that metric's absence). The heartbeat fires only
after `run_fleet_watch()` completes without raising — a heartbeat that
fires regardless of whether the run actually worked would defeat the
point.

Minimal CloudWatch-native version (Lambda receives the ping, bumps a
custom metric; alarm on `TreatMissingData: breaching` catches silence):

```bash
aws cloudwatch put-metric-alarm \
  --alarm-name certmanager-fleet-watch-heartbeat \
  --namespace CertManager \
  --metric-name FleetWatchHeartbeat \
  --statistic SampleCount \
  --period 3600 \
  --evaluation-periods 1 \
  --threshold 1 \
  --comparison-operator LessThanThreshold \
  --treat-missing-data breaching \
  --alarm-actions <SNS_TOPIC_ARN_NOT_SLACK>
```

Period should be comfortably longer than `scripts/fleet_watch.py`'s
timer interval so a single slow run doesn't false-positive.

## 3. Optional: external synthetic check

If `LIVENESS_TOKEN` is set in `.env`, `GET /api/live/{LIVENESS_TOKEN}`
returns `200 {"ok": true, ...}` with no auth — safe for CloudWatch
Synthetics, an uptime service, or a load balancer health check that
can't hold an admin session or a site token. Leave `LIVENESS_TOKEN`
unset to disable the route entirely (it 404s either way, so its
presence doesn't leak).

Pick a token the way you'd pick a password, not a slug — it's the only
thing standing between this route and being a bare public `/healthz`.
