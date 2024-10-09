# Server Faults

## 5xx Alert Policy

This alert fires when the Token Minter Cloud Run service is experiencing server faults. The alert policy monitors the `request-count` metric and checks for the response code class 5xx.

### Triage Steps

1. Navigate to Log Explorer and set the date range to match the range when the error was observed.
2. Query for `severity=ERROR jsonPayload.code=~"5[0-9][0-9]+" resource.type="cloud_run_revision"`.
3. Review the results for root cause of server faults.
