# ForwardProgressFailed

## Request Count Failing / Missing

This alert fires when the Cloud Run Service has not made forward progress in an acceptable amount of time. 

- `github-token-minter-XXXX` - This is the service triggered when a token is being requested.

### Token Minter Service Triage Steps

To begin triage, find the root cause by doing the following:

1. Go to the Cloud Run page in your GCP project.
2. Confirm the selected tab is Services (this is the default).
3. Select the token minter service and select the Revisions tab.
4. Ensure the latest deployment is successful, if not review the logs under the Logs tab and review for errors.
5. If the latest service revision is successful, or there are no errors, then consider increasing the time window.
