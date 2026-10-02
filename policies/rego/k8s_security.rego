package vulnpilot.kubernetes

# Deny privileged pods
deny[msg] {
    input.kind == "Pod"
    container := input.spec.containers[_]
    container.securityContext.privileged == true
    msg := sprintf("Container '%v' is privileged. Privileged pods are not allowed.", [container.name])
}

# Deny pods running as root
deny[msg] {
    input.kind == "Pod"
    not input.spec.securityContext.runAsNonRoot
    msg := "Pod spec does not set runAsNonRoot: true"
}

deny[msg] {
    input.kind == "Pod"
    input.spec.securityContext.runAsUser == 0
    msg := "Pod spec sets runAsUser: 0 (root)"
}

# Deny missing resource limits
deny[msg] {
    input.kind == "Pod"
    container := input.spec.containers[_]
    not container.resources.limits
    msg := sprintf("Container '%v' has no resource limits defined.", [container.name])
}

# Deny hostPath volumes
deny[msg] {
    input.kind == "Pod"
    volume := input.spec.volumes[_]
    volume.hostPath
    msg := sprintf("Volume '%v' uses hostPath which is not allowed.", [volume.name])
}

# Deny hostNetwork
deny[msg] {
    input.kind == "Pod"
    input.spec.hostNetwork == true
    msg := "Pod spec sets hostNetwork: true"
}

# Deny 'latest' image tags
deny[msg] {
    input.kind == "Pod"
    container := input.spec.containers[_]
    endswith(container.image, ":latest")
    msg := sprintf("Container '%v' uses ':latest' image tag. Pin to a specific digest.", [container.name])
}

# Deny missing readOnlyRootFilesystem
deny[msg] {
    input.kind == "Pod"
    container := input.spec.containers[_]
    not container.securityContext.readOnlyRootFilesystem
    msg := sprintf("Container '%v' does not set readOnlyRootFilesystem: true", [container.name])
}
