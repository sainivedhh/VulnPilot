package vulnpilot.kubernetes

test_privileged_denied {
    deny["Container 'evil' is privileged. Privileged pods are not allowed."] with input as {
        "kind": "Pod",
        "spec": {
            "securityContext": {"runAsNonRoot": true},
            "containers": [{
                "name": "evil",
                "image": "myapp:1.0",
                "securityContext": {"privileged": true, "readOnlyRootFilesystem": true},
                "resources": {"limits": {"cpu": "100m"}}
            }]
        }
    }
}

test_root_user_denied {
    deny["Pod spec sets runAsUser: 0 (root)"] with input as {
        "kind": "Pod",
        "spec": {
            "securityContext": {"runAsNonRoot": true, "runAsUser": 0},
            "containers": [{
                "name": "app",
                "image": "myapp:1.0",
                "securityContext": {"readOnlyRootFilesystem": true},
                "resources": {"limits": {"cpu": "100m"}}
            }]
        }
    }
}

test_no_resource_limits_denied {
    deny["Container 'app' has no resource limits defined."] with input as {
        "kind": "Pod",
        "spec": {
            "securityContext": {"runAsNonRoot": true},
            "containers": [{
                "name": "app",
                "image": "myapp:1.0",
                "securityContext": {"readOnlyRootFilesystem": true}
            }]
        }
    }
}

test_latest_tag_denied {
    deny["Container 'app' uses ':latest' image tag. Pin to a specific digest."] with input as {
        "kind": "Pod",
        "spec": {
            "securityContext": {"runAsNonRoot": true},
            "containers": [{
                "name": "app",
                "image": "myapp:latest",
                "securityContext": {"readOnlyRootFilesystem": true},
                "resources": {"limits": {"cpu": "100m"}}
            }]
        }
    }
}

test_hostpath_denied {
    deny["Volume 'host-vol' uses hostPath which is not allowed."] with input as {
        "kind": "Pod",
        "spec": {
            "securityContext": {"runAsNonRoot": true},
            "volumes": [{"name": "host-vol", "hostPath": {"path": "/etc"}}],
            "containers": [{
                "name": "app",
                "image": "myapp:1.0",
                "securityContext": {"readOnlyRootFilesystem": true},
                "resources": {"limits": {"cpu": "100m"}}
            }]
        }
    }
}

test_hostnetwork_denied {
    deny["Pod spec sets hostNetwork: true"] with input as {
        "kind": "Pod",
        "spec": {
            "hostNetwork": true,
            "securityContext": {"runAsNonRoot": true},
            "containers": [{
                "name": "app",
                "image": "myapp:1.0",
                "securityContext": {"readOnlyRootFilesystem": true},
                "resources": {"limits": {"cpu": "100m"}}
            }]
        }
    }
}

test_no_readonly_rootfs_denied {
    deny["Container 'app' does not set readOnlyRootFilesystem: true"] with input as {
        "kind": "Pod",
        "spec": {
            "securityContext": {"runAsNonRoot": true},
            "containers": [{
                "name": "app",
                "image": "myapp:1.0",
                "securityContext": {},
                "resources": {"limits": {"cpu": "100m"}}
            }]
        }
    }
}

test_compliant_pod_passes {
    count(deny) == 0 with input as {
        "kind": "Pod",
        "spec": {
            "securityContext": {"runAsNonRoot": true, "runAsUser": 1000},
            "containers": [{
                "name": "app",
                "image": "myapp:1.2.3",
                "securityContext": {
                    "readOnlyRootFilesystem": true,
                    "allowPrivilegeEscalation": false,
                    "privileged": false
                },
                "resources": {
                    "limits": {"cpu": "500m", "memory": "256Mi"},
                    "requests": {"cpu": "100m", "memory": "128Mi"}
                }
            }]
        }
    }
}
