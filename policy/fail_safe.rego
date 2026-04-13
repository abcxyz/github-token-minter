package minty.policy

# Fail-safe: Only allow token requests from a specific enterprise, org, and repo ID.
# Replace these values with your actual allowed IDs.
allowed_enterprise_id := "YOUR_ENTERPRISE_ID"
allowed_org_id := "YOUR_ORG_ID"
allowed_repo_id := "YOUR_REPO_ID"

# Deny if enterprise ID is present and does not match
deny contains msg if {
    ent_id := input.token.enterprise_id
    ent_id != allowed_enterprise_id
    msg := sprintf("invalid enterprise ID %q", [ent_id])
}

# Deny if org ID does not match
deny contains msg if {
    org_id := input.token.repository_owner_id
    org_id != allowed_org_id
    msg := sprintf("invalid org ID %q", [org_id])
}

# Deny if repo ID does not match
deny contains msg if {
    repo_id := input.token.repository_id
    repo_id != allowed_repo_id
    msg := sprintf("invalid repo ID %q", [repo_id])
}
