# Kubernetes Cluster Scanning Examples

This directory contains guidance for scanning live Kubernetes clusters.

## Prerequisites

You need a running Kubernetes cluster and `kubectl` configured to access it.

### Option 1: Local Minikube Cluster (Recommended for Testing)

```bash
# Install minikube
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube

# Start cluster
minikube start

# Verify
kubectl get nodes
```

### Option 2: Kind (Kubernetes in Docker)

```bash
# Install kind
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind

# Create cluster
kind create cluster --name test-cluster

# Verify
kubectl cluster-info --context kind-test-cluster
```

### Option 3: Docker Desktop Kubernetes

Enable Kubernetes in Docker Desktop settings.

## Scanning Kubernetes Clusters

### Scan Current Context (Default Namespace)

```bash
jmotools balanced --k8s-context $(kubectl config current-context)
```

### Scan All Namespaces

```bash
jmotools balanced --k8s-context $(kubectl config current-context) --k8s-all-namespaces
```

### Scan Specific Namespace

```bash
jmotools balanced --k8s-context minikube --k8s-namespace kube-system
```

### List Available Contexts

```bash
kubectl config get-contexts
```

## What Gets Scanned

JMo Security scans Kubernetes clusters for:

- **Vulnerabilities** in container images running in pods (Trivy)
- **Misconfigurations** in workload manifests
- **RBAC issues** (overly permissive roles/bindings)
- **Network policies** (missing or weak policies)
- **Secret management** issues
- **Pod security** context violations

## Example Workflow

```bash
# 1. Start local cluster
minikube start

# 2. Deploy test workload with known issues
kubectl apply -f ../iac-files/kubernetes-deployment.yaml

# 3. Scan the cluster
jmotools balanced \
  --k8s-context minikube \
  --k8s-namespace test-namespace \
  --results-dir ./k8s-scan-results

# 4. View results
open k8s-scan-results/summaries/dashboard.html
```

## Important Notes

- **Never scan production clusters without authorization**
- Scanning requires read permissions (get, list) on cluster resources
- Large clusters may take 10-30 minutes to scan
- Use `--k8s-namespace` to limit scope and reduce scan time
- Trivy requires network access to pull vulnerability databases

## Cleanup

```bash
# Delete test namespace
kubectl delete namespace test-namespace

# Stop minikube
minikube stop

# Delete kind cluster
kind delete cluster --name test-cluster
```
