# Kubernetes Security Remediation

## Problem Description

The current Kubernetes deployment configuration contains multiple security vulnerabilities including running as root, missing security contexts, mounting sensitive host paths, and hardcoded secrets.

## Current Vulnerable Kubernetes Issues

1. **No security context** - Running with default (root) permissions
2. **Hardcoded secrets** - Secrets embedded in deployment manifests
3. **Mounting sensitive paths** - Host filesystem and Docker socket exposed
4. **No resource limits** - Potential for resource exhaustion
5. **Privileged containers** - Running with excessive privileges
6. **No network policies** - Unrestricted network access
7. **Missing admission controls** - No Pod Security Standards

## Secure Kubernetes Deployment

### 1. Secure Deployment with Security Context

```yaml
# secure-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnerable-app
  namespace: vulnerable-app-ns
  labels:
    app: vulnerable-app
    version: "1.0"
spec:
  replicas: 2
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
      maxSurge: 1
  selector:
    matchLabels:
      app: vulnerable-app
  template:
    metadata:
      labels:
        app: vulnerable-app
        version: "1.0"
      annotations:
        # Security: Pod security annotations
        seccomp.security.alpha.kubernetes.io/pod: runtime/default
    spec:
      # Security: Service account with minimal permissions
      serviceAccountName: vulnerable-app-sa
      
      # Security: Pod security context
      securityContext:
        runAsNonRoot: true
        runAsUser: 1001
        runAsGroup: 1001
        fsGroup: 1001
        fsGroupChangePolicy: "OnRootMismatch"
        seccompProfile:
          type: RuntimeDefault
        supplementalGroups: []
      
      containers:
      - name: vulnerable-app
        image: vulnerable-app:1.0
        imagePullPolicy: Always
        
        ports:
        - containerPort: 8080
          name: http
          protocol: TCP
        
        # Security: Container security context
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          runAsUser: 1001
          runAsGroup: 1001
          capabilities:
            drop:
              - ALL
          seccompProfile:
            type: RuntimeDefault
        
        # Security: Resource limits
        resources:
          limits:
            cpu: 500m
            memory: 512Mi
            ephemeral-storage: 1Gi
          requests:
            cpu: 250m
            memory: 256Mi
            ephemeral-storage: 512Mi
        
        # Security: Environment variables from secrets
        env:
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: vulnerable-app-secrets
              key: db-password
        - name: API_KEY
          valueFrom:
            secretKeyRef:
              name: vulnerable-app-secrets
              key: api-key
        - name: JWT_SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: vulnerable-app-secrets
              key: jwt-secret
        
        # Security: Volume mounts (read-only where possible)
        volumeMounts:
        - name: tmp-volume
          mountPath: /tmp
        - name: data-volume
          mountPath: /app/data
        - name: config-volume
          mountPath: /app/config
          readOnly: true
        
        # Security: Liveness and readiness probes
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
            scheme: HTTP
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          successThreshold: 1
          failureThreshold: 3
        
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
            scheme: HTTP
          initialDelaySeconds: 5
          periodSeconds: 5
          timeoutSeconds: 3
          successThreshold: 1
          failureThreshold: 3
      
      # Security: Volumes (no host mounts)
      volumes:
      - name: tmp-volume
        emptyDir:
          sizeLimit: 100Mi
      - name: data-volume
        emptyDir:
          sizeLimit: 1Gi
      - name: config-volume
        configMap:
          name: vulnerable-app-config
          defaultMode: 0444
      
      # Security: Node selection and anti-affinity
      nodeSelector:
        kubernetes.io/os: linux
      
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            podAffinityTerm:
              labelSelector:
                matchExpressions:
                - key: app
                  operator: In
                  values:
                  - vulnerable-app
              topologyKey: kubernetes.io/hostname
      
      # Security: Tolerations (if needed)
      tolerations: []
      
      # Security: DNS policy
      dnsPolicy: ClusterFirst
      
      # Security: Termination grace period
      terminationGracePeriodSeconds: 30
```

### 2. Secure Service Account and RBAC

```yaml
# service-account.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: vulnerable-app-sa
  namespace: vulnerable-app-ns
  labels:
    app: vulnerable-app
automountServiceAccountToken: false

---
# RBAC for minimal permissions
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: vulnerable-app-ns
  name: vulnerable-app-role
rules:
# Minimal permissions - only what the app needs
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list"]
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get"]
  resourceNames: ["vulnerable-app-secrets"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: vulnerable-app-rolebinding
  namespace: vulnerable-app-ns
subjects:
- kind: ServiceAccount
  name: vulnerable-app-sa
  namespace: vulnerable-app-ns
roleRef:
  kind: Role
  name: vulnerable-app-role
  apiGroup: rbac.authorization.k8s.io
```

### 3. Secure Secrets Management

```yaml
# secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: vulnerable-app-secrets
  namespace: vulnerable-app-ns
  labels:
    app: vulnerable-app
type: Opaque
data:
  # Security: Base64 encoded secrets (use external secret management in production)
  db-password: c3VwZXJzZWNyZXQxMjM=  # supersecret123
  api-key: YWRtaW4tc2VjcmV0LWtleQ==     # admin-secret-key
  jwt-secret: bXktc2VjdXJlLWp3dC1zZWNyZXQ=  # my-secure-jwt-secret

---
# ConfigMap for non-sensitive configuration
apiVersion: v1
kind: ConfigMap
metadata:
  name: vulnerable-app-config
  namespace: vulnerable-app-ns
  labels:
    app: vulnerable-app
data:
  app.yaml: |
    server:
      port: 8080
      read_timeout: 30s
      write_timeout: 30s
      idle_timeout: 60s
    database:
      driver: sqlite3
      path: /app/data/vulnerable.db
    security:
      session_timeout: 900  # 15 minutes
      max_login_attempts: 5
      lockout_duration: 300  # 5 minutes
```

### 4. Network Policies

```yaml
# network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: vulnerable-app-netpol
  namespace: vulnerable-app-ns
spec:
  podSelector:
    matchLabels:
      app: vulnerable-app
  policyTypes:
  - Ingress
  - Egress
  
  ingress:
  # Allow ingress from ingress controller
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 8080
  
  # Allow ingress from monitoring (if needed)
  - from:
    - namespaceSelector:
        matchLabels:
          name: monitoring
    ports:
    - protocol: TCP
      port: 8080
  
  egress:
  # Allow DNS resolution
  - to: []
    ports:
    - protocol: UDP
      port: 53
  
  # Allow HTTPS to external services (for updates, etc.)
  - to: []
    ports:
    - protocol: TCP
      port: 443
  
  # Allow communication within namespace
  - to:
    - namespaceSelector:
        matchLabels:
          name: vulnerable-app-ns
```

### 5. Pod Security Standards

```yaml
# pod-security-policy.yaml (deprecated in K8s 1.25+)
# Use Pod Security Standards instead

# Namespace with Pod Security Standards
apiVersion: v1
kind: Namespace
metadata:
  name: vulnerable-app-ns
  labels:
    # Pod Security Standards enforcement
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
    # Admission controller configuration
    pod-security.kubernetes.io/enforce-version: latest
```

### 6. Security Monitoring and Policies

```yaml
# falco-rules.yaml (if using Falco)
apiVersion: v1
kind: ConfigMap
metadata:
  name: falco-rules
  namespace: falco-system
data:
  vulnerable-app-rules.yaml: |
    - rule: Vulnerable App Suspicious Activity
      desc: Detect suspicious activity in vulnerable app
      condition: >
        spawned_process and
        proc.pname = "vulnerable-app" and
        (proc.name in (shell_binaries) or 
         proc.args contains "curl" or
         proc.args contains "wget")
      output: >
        Suspicious process spawned by vulnerable app
        (user=%user.name process=%proc.name parent=%proc.pname cmdline=%proc.cmdline)
      priority: WARNING
      tags: [process, suspicious]

    - rule: Vulnerable App Network Anomaly
      desc: Detect unexpected network connections
      condition: >
        outbound and
        container.name = "vulnerable-app" and
        not fd.net.ip in (allowed_ips)
      output: >
        Unexpected outbound connection from vulnerable app
        (connection=%fd.name)
      priority: WARNING
      tags: [network, anomaly]
```

## Advanced Security Configurations

### 1. OPA Gatekeeper Policies

```yaml
# gatekeeper-policy.yaml
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: vulnerableappsecurity
spec:
  crd:
    spec:
      names:
        kind: VulnerableAppSecurity
      validation:
        openAPIV3Schema:
          type: object
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package vulnerableappsecurity
        
        violation[{"msg": msg}] {
          input.review.object.kind == "Pod"
          input.review.object.metadata.labels.app == "vulnerable-app"
          input.review.object.spec.securityContext.runAsUser == 0
          msg := "Vulnerable app cannot run as root"
        }
        
        violation[{"msg": msg}] {
          input.review.object.kind == "Pod"
          input.review.object.metadata.labels.app == "vulnerable-app"
          not input.review.object.spec.securityContext.readOnlyRootFilesystem
          msg := "Vulnerable app must use read-only root filesystem"
        }

---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: VulnerableAppSecurity
metadata:
  name: vulnerable-app-security-policy
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    namespaces: ["vulnerable-app-ns"]
```

### 2. Admission Controller Webhook

```yaml
# admission-webhook.yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionWebhook
metadata:
  name: vulnerable-app-validator
webhooks:
- name: pod.vulnerable-app.validator
  clientConfig:
    service:
      name: vulnerable-app-admission-webhook
      namespace: vulnerable-app-ns
      path: "/validate-pods"
  rules:
  - operations: ["CREATE", "UPDATE"]
    apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods"]
  namespaceSelector:
    matchLabels:
      name: vulnerable-app-ns
  admissionReviewVersions: ["v1", "v1beta1"]
  sideEffects: None
  failurePolicy: Fail
```

## Implementation Steps

### Step 1: Create Namespace with Security Labels
```bash
kubectl create namespace vulnerable-app-ns
kubectl label namespace vulnerable-app-ns \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted
```

### Step 2: Apply Security Configurations
```bash
# Apply RBAC and service account
kubectl apply -f service-account.yaml

# Create secrets (use external secret management in production)
kubectl apply -f secrets.yaml

# Apply network policies
kubectl apply -f network-policy.yaml

# Deploy application
kubectl apply -f secure-deployment.yaml
```

### Step 3: Verify Security Configuration
```bash
# Check pod security context
kubectl describe pod -l app=vulnerable-app -n vulnerable-app-ns

# Verify no root processes
kubectl exec -it deployment/vulnerable-app -n vulnerable-app-ns -- ps aux

# Check network policies
kubectl describe networkpolicy vulnerable-app-netpol -n vulnerable-app-ns

# Verify resource limits
kubectl describe pod -l app=vulnerable-app -n vulnerable-app-ns | grep -A 10 "Limits:"
```

## Security Testing for Kubernetes

### Security Test Script
```bash
#!/bin/bash
# scripts/k8s-security-test.sh

echo "🔒 Running Kubernetes Security Tests..."

NAMESPACE="vulnerable-app-ns"
APP_LABEL="app=vulnerable-app"

# Test 1: Verify pods are not running as root
echo "Testing: Pods not running as root..."
ROOT_PODS=$(kubectl get pods -l $APP_LABEL -n $NAMESPACE -o jsonpath='{.items[*].spec.securityContext.runAsUser}' | grep -c "^0$" || true)
if [ "$ROOT_PODS" -gt 0 ]; then
    echo "❌ FAIL: Found pods running as root"
    exit 1
else
    echo "✅ PASS: No pods running as root"
fi

# Test 2: Verify read-only root filesystem
echo "Testing: Read-only root filesystem..."
RW_ROOT=$(kubectl get pods -l $APP_LABEL -n $NAMESPACE -o jsonpath='{.items[*].spec.containers[*].securityContext.readOnlyRootFilesystem}' | grep -c "false" || true)
if [ "$RW_ROOT" -gt 0 ]; then
    echo "❌ FAIL: Found containers with writable root filesystem"
    exit 1
else
    echo "✅ PASS: All containers use read-only root filesystem"
fi

# Test 3: Verify no privileged containers
echo "Testing: No privileged containers..."
PRIVILEGED=$(kubectl get pods -l $APP_LABEL -n $NAMESPACE -o jsonpath='{.items[*].spec.containers[*].securityContext.privileged}' | grep -c "true" || true)
if [ "$PRIVILEGED" -gt 0 ]; then
    echo "❌ FAIL: Found privileged containers"
    exit 1
else
    echo "✅ PASS: No privileged containers"
fi

# Test 4: Verify resource limits are set
echo "Testing: Resource limits..."
NO_LIMITS=$(kubectl get pods -l $APP_LABEL -n $NAMESPACE -o jsonpath='{.items[*].spec.containers[*].resources.limits}' | grep -c "map\[\]" || true)
if [ "$NO_LIMITS" -gt 0 ]; then
    echo "❌ FAIL: Found containers without resource limits"
    exit 1
else
    echo "✅ PASS: All containers have resource limits"
fi

# Test 5: Verify network policies exist
echo "Testing: Network policies..."
NETPOL_COUNT=$(kubectl get networkpolicies -n $NAMESPACE --no-headers | wc -l)
if [ "$NETPOL_COUNT" -eq 0 ]; then
    echo "❌ FAIL: No network policies found"
    exit 1
else
    echo "✅ PASS: Network policies are configured"
fi

echo "✅ All Kubernetes security tests passed!"
```

### Pod Security Standards Validation
```bash
# Validate against Pod Security Standards
kubectl label --dry-run=server namespace vulnerable-app-ns \
  pod-security.kubernetes.io/enforce=restricted

# Check for violations
kubectl get events -n vulnerable-app-ns --field-selector reason=FailedCreate
```

## Security Monitoring

### 1. Falco Rules for Runtime Security
```yaml
# Install Falco for runtime security monitoring
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco \
  --namespace falco-system \
  --create-namespace \
  --set falco.grpc.enabled=true \
  --set falco.grpcOutput.enabled=true
```

### 2. Security Scanning with Twistlock/Prisma
```yaml
# twistlock-daemonset.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: twistlock-defender
  namespace: twistlock
spec:
  selector:
    matchLabels:
      app: twistlock-defender
  template:
    metadata:
      labels:
        app: twistlock-defender
    spec:
      containers:
      - name: twistlock-defender
        image: registry.twistlock.com/twistlock/defender:defender_<VERSION>
        # Security configuration for defender
        securityContext:
          privileged: true
        volumeMounts:
        - name: docker-sock
          mountPath: /var/run/docker.sock
        - name: host-root
          mountPath: /host
          readOnly: true
      volumes:
      - name: docker-sock
        hostPath:
          path: /var/run/docker.sock
      - name: host-root
        hostPath:
          path: /
      hostNetwork: true
      hostPID: true
```

## Best Practices Summary

### Security Context Best Practices
1. **Never run as root** - Always set `runAsNonRoot: true`
2. **Use read-only filesystem** - Set `readOnlyRootFilesystem: true`
3. **Drop capabilities** - Remove all unnecessary capabilities
4. **Set user/group IDs** - Use non-root user IDs (>= 1000)
5. **Enable seccomp** - Use `RuntimeDefault` seccomp profile

### Resource Management
1. **Set resource limits** - Prevent resource exhaustion
2. **Use namespaces** - Isolate workloads
3. **Implement network policies** - Control network traffic
4. **Monitor resource usage** - Track CPU, memory, storage

### Secrets Management
1. **External secret management** - Use Vault, AWS Secrets Manager, etc.
2. **Rotate secrets regularly** - Implement secret rotation
3. **Limit secret access** - Use RBAC to control access
4. **Audit secret usage** - Monitor secret access

## Tools for Kubernetes Security

### Scanning Tools
- **kube-bench** - CIS Kubernetes Benchmark
- **kube-hunter** - Kubernetes penetration testing
- **Polaris** - Configuration validation
- **OPA Gatekeeper** - Policy enforcement

### Runtime Security
- **Falco** - Runtime threat detection
- **Sysdig Secure** - Container security platform
- **Twistlock/Prisma Cloud** - Container security
- **Aqua Security** - Container security platform

### Compliance Tools
- **Starboard** - Kubernetes security toolkit
- **Cluster Scanner** - Security scanning operator
- **Kubernetes Security Benchmark** - Compliance checking

## Additional Resources

- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [NIST Kubernetes Security Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf)