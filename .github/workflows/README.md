# GitHub Actions Workflows

This directory contains GitHub Actions workflows for the Nautilus Watermark Service.

## Workflows

### 1. Rust CI (`rust.yml`)

**Triggers:**
- Push to any branch
- Pull requests

**Purpose:** Continuous integration checks for code quality

**Steps:**
- License checking
- Unit tests
- Clippy linting
- Rustfmt formatting
- Cargo-deny security checks

### 2. Deploy to Nitro Enclave (`deploy-enclave.yml`)

**Triggers:**
- Push to `main` branch (automatic deployment to staging)
- Manual workflow dispatch (with environment selection)

**Purpose:** Build EIF file and deploy to AWS Nitro Enclaves

**Environments:**
- `staging` - Automatic deployment on push to main
- `production` - Manual deployment only

**Required Setup:**

1. **AWS IAM Role:**
   - Role ARN: `arn:aws:iam::287767576800:role/github-actions-cicd-role`
   - Must have permissions for:
     - S3: PutObject, GetObject on `zing-enclave-artifacts-*` buckets
     - Terraform state access (if auto-apply enabled)

2. **GitHub Secrets:**
   - `GITHUB_TOKEN` - Automatically provided by GitHub Actions
   - Ensure the repository has access to the `zing` repository (for Terraform updates)

**Workflow Steps:**

1. **Checkout Code** - Get the latest source code
2. **Determine Environment** - staging (auto) or production (manual)
3. **Get Commit SHA** - Short commit hash for versioning
4. **Configure AWS** - Authenticate using OIDC
5. **Check S3** - Skip build if EIF already exists
6. **Build EIF** - Compile Nitro Enclave image using Docker
7. **Upload to S3** - Store EIF file with version tag
8. **Update Terraform** - Modify `eif_version` in infrastructure config
9. **Create PR** - Open pull request for Terraform changes (or auto-apply for staging)

**Deployment Modes:**

### Automatic (Staging)
- Triggered on push to `main`
- Builds EIF if needed
- Uploads to S3
- Creates PR for Terraform changes
- Auto-applies Terraform (staging only)

### Manual (Production)
- Triggered via GitHub Actions UI
- Select environment (staging/production)
- Option to auto-apply Terraform changes
- Requires manual confirmation for production

**EIF File Naming:**
- Format: `nitro-{commit_sha}.eif`
- Example: `nitro-8e87460.eif`
- Stored in: `s3://zing-enclave-artifacts-{env}/eif/{env}/`

**Terraform Integration:**

The workflow automatically:
1. Checks out the `zing-infra` repository
2. Updates `eif_version` in the environment's `main.tf`
3. Creates a PR with the changes
4. Optionally applies changes automatically (staging only)

**Example Usage:**

```bash
# Automatic deployment (on push to main)
git push origin main

# Manual deployment via GitHub UI
# 1. Go to Actions > Deploy to Nitro Enclave
# 2. Click "Run workflow"
# 3. Select environment
# 4. Choose auto-apply option
```

**Troubleshooting:**

**Build fails:**
- Check Docker is available in runner
- Verify `ENCLAVE_APP=zing-watermark` is correct
- Review Containerfile for build issues

**S3 upload fails:**
- Verify IAM role has S3 permissions
- Check bucket name is correct
- Ensure region matches (ap-northeast-1)

**Terraform update fails:**
- Verify repository has access to `zing-infra`
- Check `GITHUB_TOKEN` permissions
- Review Terraform backend configuration

**Enclave doesn't start:**
- Check CloudWatch logs: `/aws/ec2/nautilus-watermark-{env}`
- Verify EIF file exists in S3
- Review user-data script execution

## Local Development

For local testing before pushing:

```bash
# Build EIF locally
make ENCLAVE_APP=zing-watermark

# Upload to S3 manually
COMMIT_SHA=$(git rev-parse --short HEAD)
aws s3 cp out/nitro.eif \
  s3://zing-enclave-artifacts-staging/eif/staging/nitro-${COMMIT_SHA}.eif

# Update Terraform manually
cd zing-infra/environments/staging/nautilus-enclave
terraform apply -var="eif_version=${COMMIT_SHA}"
```

