# Request Latency

## P99 Latency High

This alert fires when the Cloud Run service is experiencing a high level of request latency. The alert policy monitors the `request_latencies` metric and samples for the P99 latency.

### Triage Steps

1. Go to the Cloud Run page in your GCP project.
2. Confirm the selected tab is Services (this is the default).
3. Select the token minter service and select the Metrics tab.
4. Review the latency graph and look for the latent time frame. 
5. Navigate to Trace Explorer in Cloud Monitoring.
6. Sort by highest latency and ensure the relative time frame includes the time when the spike occurred.
7. Select the failing span and view the Logs & Events tab and view the error log.
