---
name: implementing-gcp-binary-authorization
description: Implement GCP Binary Authorization to enforce Dağıt:-time security controls that ensure only trusted, attested container images are Dağıtılmış to Google Kubernetes Engine and Cloud Run.
tags:
- cybersecurity
- binary-authorization
- attestation
- siber-güvenlik
- gcp
- container-security
- software-integrity
- fetih
- cloud-security
- cloud-run
- supply-chain
- gke
triggers:
- AWS
- Azure
- GCP
- api
- authorization
- binary
- bulut güvenliği
- cloud
- cloud security
- container
- crypto
- http
category: cloud-security
source_subdomain: cloud-security
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
---

# Implementing Gcp Binary Authorization


## Genel Bakış

Binary Authorization is a Google Cloud Dağıt:-time security control that ensures only trusted container images are Dağıtılmış on GKE or Cloud Run. It works through a policy-based model where images must have cryptographic attestations confirming they passed predefined requirements such as vulnerability scans, code reviews, or build pipeline verification. Continuous validation (CV) monitors running pods against policies and logs violations.


## Ne Zaman Kullanılır

- Dağıt:ing yaparken or configuring implementing gcp binary authorization capabilities in your environment
- establishing yaparken: security controls aligned to compliance requirements
- building yaparken or improving security architecture for this domain
- conducting yaparken security assessments that require this implementation

## Ön Gereksinimler

- GCP project with Binary Authorization API enabled
- GKE cluster or Cloud Run service
- Container Analysis API enabled
- KMS keys for attestation signing
- Cloud Build or external CI/CD pipeline

## Enable Binary Authorization

```bash
gcloud services enable binaryauthorization.googleapis.com
gcloud services enable containeranalysis.googleapis.com
gcloud services enable container.googleapis.com

gcloud container clusters update CLUSTER_NAME \
  --enable-binauthz \
  --zone us-central1-a
```

## Şunu oluştur:ttestor

### Şunu oluştur: KMS key for signing

```bash
gcloud kms keyrings create binauthz-keyring \
  --location global

gcloud kms keys Şunu oluştur:ttestor-key \
  --keyring binauthz-keyring \
  --location global \
  --algorithm ec-sign-p256-sha256 \
  --purpose asymmetric-signing
```

### Create Container Analysis note

```bash
cat > /tmp/note.json << 'EOF'
{
  "attestation": {
    "hint": {
      "humanReadableName": "Production Build Attestor"
    }
  }
}
EOF

curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://containeranalysis.googleapis.com/v1/projects/PROJECT_ID/notes/?noteId=prod-build-note" \
  -d @/tmp/note.json
```

### Create the attestor

```bash
gcloud container binauthz attestors create prod-build-attestor \
  --attestation-authority-note=prod-build-note \
  --attestation-authority-note-project=PROJECT_ID

gcloud container binauthz attestors public-keys add \
  --attestor=prod-build-attestor \
  --keyversion-project=PROJECT_ID \
  --keyversion-location=global \
  --keyversion-keyring=binauthz-keyring \
  --keyversion-key=attestor-key \
  --keyversion=1
```

## Configure Policy

### Default deny-all policy

```yaml
admissionWhitelistPatterns:
  - namePattern: "gcr.io/google_containers/*"
  - namePattern: "gcr.io/google-containers/*"
  - namePattern: "k8s.gcr.io/**"
  - namePattern: "gke.gcr.io/**"
  - namePattern: "gcr.io/stackdriver-agents/*"
defaultAdmissionRule:
  evaluationMode: REQUIRE_ATTESTATION
  enforcementMode: ENFORCED_BLOCK_AND_AUDIT_LOG
  requireAttestationsBy:
    - projects/PROJECT_ID/attestors/prod-build-attestor
globalPolicyEvaluationMode: ENABLE
```

```bash
gcloud container binauthz policy import binauthz-policy.yaml
```

### Per-cluster rules

```yaml
admissionWhitelistPatterns:
  - namePattern: "gcr.io/google_containers/*"
clusterAdmissionRules:
  us-central1-a.production-cluster:
    evaluationMode: REQUIRE_ATTESTATION
    enforcementMode: ENFORCED_BLOCK_AND_AUDIT_LOG
    requireAttestationsBy:
      - projects/PROJECT_ID/attestors/prod-build-attestor
  us-central1-a.staging-cluster:
    evaluationMode: ALWAYS_ALLOW
    enforcementMode: DRYRUN_AUDIT_LOG_ONLY
defaultAdmissionRule:
  evaluationMode: ALWAYS_DENY
  enforcementMode: ENFORCED_BLOCK_AND_AUDIT_LOG
```

## Şunu oluştur:ttestations

### Attest an image after successful build

```bash
IMAGE_DIGEST=$(gcloud container images describe \
  gcr.io/PROJECT_ID/my-app:latest \
  --format='get(image_summary.digest)')

gcloud container binauthz attestations sign-and-create \
  --artifact-url="gcr.io/PROJECT_ID/my-app@${IMAGE_DIGEST}" \
  --attestor="prod-build-attestor" \
  --attestor-project="PROJECT_ID" \
  --keyversion-project="PROJECT_ID" \
  --keyversion-location="global" \
  --keyversion-keyring="binauthz-keyring" \
  --keyversion-key="attestor-key" \
  --keyversion="1"
```

### Cloud Build integration

```yaml
steps:
  - name: 'gcr.io/cloud-builders/docker'
    args: ['build', '-t', 'gcr.io/$PROJECT_ID/my-app:$SHORT_SHA', '.']

  - name: 'gcr.io/cloud-builders/docker'
    args: ['push', 'gcr.io/$PROJECT_ID/my-app:$SHORT_SHA']

  # Vulnerability scanning
  - name: 'gcr.io/cloud-builders/gcloud'
    entrypoint: 'bash'
    args:
      - '-c'
      - |
        gcloud artifacts docker images scan \
          gcr.io/$PROJECT_ID/my-app:$SHORT_SHA \
          --format='value(response.scan)'

  # Şunu oluştur:ttestation after successful scan
  - name: 'gcr.io/cloud-builders/gcloud'
    entrypoint: 'bash'
    args:
      - '-c'
      - |
        IMAGE_DIGEST=$(gcloud container images describe \
          gcr.io/$PROJECT_ID/my-app:$SHORT_SHA \
          --format='get(image_summary.digest)')
        gcloud container binauthz attestations sign-and-create \
          --artifact-url="gcr.io/$PROJECT_ID/my-app@$${IMAGE_DIGEST}" \
          --attestor="prod-build-attestor" \
          --attestor-project="$PROJECT_ID" \
          --keyversion-project="$PROJECT_ID" \
          --keyversion-location="global" \
          --keyversion-keyring="binauthz-keyring" \
          --keyversion-key="attestor-key" \
          --keyversion="1"
```

## Continuous Validation

```bash
gcloud container clusters update CLUSTER_NAME \
  --enable-binauthz-monitoring \
  --zone us-central1-a
```

### Monitor CV violations in Cloud Logging

```
resource.type="k8s_cluster"
logName="projects/PROJECT_ID/logs/binaryauthorization.googleapis.com%2Fcontinuous_validation"
```

## Verification and Testing

### Test Dağıt:ment of unattested image

```bash
kubectl run test-unapproved \
  --image=docker.io/library/nginx:latest

kubectl get events --field-selector reason=FailedCreate
```

### Verify attestation exists

```bash
gcloud container binauthz attestations list \
  --attestor=prod-build-attestor \
  --attestor-project=PROJECT_ID
```

## Break-Glass Override

For emergency Dağıt:ments bypassing Binary Authorization:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: emergency-pod
  labels:
    image-policy.k8s.io/break-glass: "true"
  annotations:
    alpha.image-policy.k8s.io/break-glass: "Emergency Dağıt:ment - ticket INC-12345"
spec:
  containers:
    - name: emergency
      image: gcr.io/PROJECT_ID/emergency-fix:latest
```

## References

- GCP Binary Authorization: https://cloud.google.com/binary-authorization/docs
- SLSA Framework: https://slsa.dev
- Sigstore/Cosign for container signing
- Google Software Supply Chain Security Best Practices
