package minty.policy

# Ensure no configuration allows "write" permissions in this deployment.
deny contains msg if {
    some scope_name, scope in input.config.scope
    some perm_name, perm_value in scope.permissions
    perm_value != "read"
    msg := sprintf("scope %q requests non-read permission %q: %q", [scope_name, perm_name, perm_value])
}

# Guard against empty or missing permissions which might default to "all"
deny contains msg if {
    some scope_name, scope in input.config.scope
    not scope.permissions
    msg := sprintf("scope %q has no permissions defined", [scope_name])
}

deny contains msg if {
    some scope_name, scope in input.config.scope
    count(scope.permissions) == 0
    msg := sprintf("scope %q has empty permissions", [scope_name])
}
