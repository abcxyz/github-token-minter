package minty.policy

# Ensure cross-repo tokens are only defined in the central configuration.
deny contains msg if {
    input.source != "central"
    some scope_name, scope in input.config.scope
    some repo in scope.repositories
    repo != input.repo
    msg := sprintf("scope %q requests access to other repository %q from non-central config", [scope_name, repo])
}
