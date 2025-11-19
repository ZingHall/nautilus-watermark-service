# CI/CD 設置指南

本文檔說明如何設置和運行 `deploy-enclave.yml` workflow。

## 前置需求

### 1. AWS 基礎設施

#### 1.1 GitHub Actions OIDC 配置

確保 AWS 中已配置 GitHub Actions OIDC Provider 和 IAM Role：

```bash
# 檢查是否已配置
cd zing-infra/environments/staging/cicd
terraform output github_actions_cicd_role_arn
```

如果尚未配置，需要先部署 `github-cicd` 模組：

```hcl
module "github_cicd" {
  source = "../../../modules/aws/github-cicd"
  
  repositories = [
    "ZingHall/*",  # 或 "ZingHall/nautilus-watermark-service"
  ]
  
  enable_terraform_permissions = true  # 必需：用於自動 apply Terraform
}
```

**重要**: 如果 workflow 需要自動 apply Terraform（staging 環境自動部署），必須設置 `enable_terraform_permissions = true`。

檢查當前配置：
```bash
cd zing-infra/environments/staging/cicd
cat github.tf
```

如果沒有 `enable_terraform_permissions = true`，需要更新並重新應用：
```bash
# 編輯 github.tf，添加 enable_terraform_permissions = true
terraform apply
```

**IAM Role ARN**: `arn:aws:iam::287767576800:role/github-actions-cicd-role`

#### 1.2 IAM Role 權限

確保 IAM Role 有以下權限：

**S3 權限**（必需）:
```json
{
  "Effect": "Allow",
  "Action": [
    "s3:PutObject",
    "s3:GetObject",
    "s3:ListBucket"
  ],
  "Resource": [
    "arn:aws:s3:::zing-enclave-artifacts-staging/*",
    "arn:aws:s3:::zing-enclave-artifacts-staging",
    "arn:aws:s3:::zing-enclave-artifacts-production/*",
    "arn:aws:s3:::zing-enclave-artifacts-production"
  ]
}
```

**Terraform State 權限**（如果啟用 auto-apply）:
```json
{
  "Effect": "Allow",
  "Action": [
    "s3:GetObject",
    "s3:PutObject",
    "s3:ListBucket"
  ],
  "Resource": [
    "arn:aws:s3:::terraform-zing-staging/*",
    "arn:aws:s3:::terraform-zing-staging",
    "arn:aws:s3:::terraform-zing-production/*",
    "arn:aws:s3:::terraform-zing-production"
  ]
},
{
  "Effect": "Allow",
  "Action": [
    "dynamodb:GetItem",
    "dynamodb:PutItem",
    "dynamodb:DeleteItem"
  ],
  "Resource": "arn:aws:dynamodb:ap-northeast-1:287767576800:table/terraform-lock-table"
}
```

#### 1.3 S3 Buckets

確保以下 S3 buckets 已創建：

- `zing-enclave-artifacts-staging` - 存儲 staging 環境的 EIF 文件
- `zing-enclave-artifacts-production` - 存儲 production 環境的 EIF 文件

這些通常由 Terraform 自動創建（在 `nautilus-enclave` 模組中）。

#### 1.4 Terraform Backend

確保 Terraform backend 已配置：

- **S3 Bucket**: `terraform-zing-staging` 和 `terraform-zing-production`
- **DynamoDB Table**: `terraform-lock-table`
- **Region**: `ap-northeast-1`

### 2. GitHub 倉庫設置

#### 2.1 倉庫權限

確保以下倉庫存在且可訪問：

1. **nautilus-watermark-service** - 當前倉庫（包含 workflow）
2. **zing-infra** - Infrastructure 倉庫（`ZingHall/zing-infra`）

#### 2.2 GitHub Actions 權限

在倉庫設置中啟用 GitHub Actions：

1. 前往 `Settings` > `Actions` > `General`
2. 確保 "Allow all actions and reusable workflows" 已啟用
3. 確保 "Read and write permissions" 已啟用（用於創建 PR）

#### 2.3 GitHub Token

`GITHUB_TOKEN` 會自動提供，但需要確保有以下權限：

- `contents: read` - 讀取倉庫內容
- `pull-requests: write` - 創建 Pull Request
- `id-token: write` - OIDC 認證

這些權限在 workflow 中已通過 `permissions` 設置。

### 3. 本地開發環境（可選）

如果需要本地測試：

```bash
# 安裝 Docker（用於構建 EIF）
# macOS
brew install docker

# 安裝 AWS CLI
brew install awscli

# 配置 AWS 憑證
aws configure --profile zing-staging
```

## 驗證設置

### 1. 檢查 AWS IAM Role

```bash
# 檢查 Role 是否存在
aws iam get-role --role-name github-actions-cicd-role --region ap-northeast-1

# 檢查 OIDC Provider
aws iam list-open-id-connect-providers
```

### 2. 檢查 S3 Buckets

```bash
# 檢查 staging bucket
aws s3 ls s3://zing-enclave-artifacts-staging/

# 檢查 production bucket
aws s3 ls s3://zing-enclave-artifacts-production/
```

### 3. 檢查 GitHub 倉庫

```bash
# 確認倉庫可訪問
gh repo view ZingHall/zing-infra

# 確認 workflow 文件存在
gh workflow list --repo ZingHall/nautilus-watermark-service
```

## 首次運行

### 1. 手動觸發 Workflow

1. 前往 GitHub 倉庫頁面
2. 點擊 `Actions` 標籤
3. 選擇 "Deploy to Nitro Enclave" workflow
4. 點擊 "Run workflow"
5. 選擇環境（staging 或 production）
6. 選擇是否自動 apply Terraform
7. 點擊 "Run workflow"

### 2. 監控執行

- 在 Actions 頁面查看執行日誌
- 檢查每個步驟的輸出
- 查看 Deployment Summary

### 3. 驗證部署

```bash
# 檢查 EIF 文件是否上傳到 S3
aws s3 ls s3://zing-enclave-artifacts-staging/eif/staging/

# 檢查 Terraform 是否更新
cd zing-infra/environments/staging/nautilus-enclave
terraform plan
```

## 常見問題

### 問題 1: "Not authorized to perform sts:AssumeRoleWithWebIdentity"

**原因**: IAM Role 的信任策略中沒有包含當前倉庫

**解決方案**:
1. 檢查 `github-cicd` 模組的 `repositories` 配置
2. 確保包含 `ZingHall/nautilus-watermark-service` 或 `ZingHall/*`
3. 重新應用 Terraform

### 問題 2: "Access Denied" 當上傳到 S3

**原因**: IAM Role 沒有 S3 權限

**解決方案**:
1. 檢查 IAM Role 的 policy
2. 確保有 `s3:PutObject` 和 `s3:GetObject` 權限
3. 確保 Resource ARN 正確

### 問題 3: "Repository not found" 當 checkout zing-infra

**原因**: 
- 倉庫不存在
- 倉庫名稱錯誤
- 沒有訪問權限

**解決方案**:
1. 確認 `ZingHall/zing-infra` 倉庫存在
2. 確認 `github.repository_owner` 返回正確的值
3. 檢查倉庫是否為私有（需要 token）

### 問題 4: "Terraform backend initialization failed"

**原因**: Terraform backend 配置錯誤或權限不足

**解決方案**:
1. 檢查 S3 bucket 是否存在
2. 檢查 DynamoDB table 是否存在
3. 確認 IAM Role 有 backend 權限
4. 檢查 backend 配置是否正確

### 問題 5: "EIF build failed"

**原因**: Docker 構建失敗

**解決方案**:
1. 檢查 `Containerfile` 是否正確
2. 檢查 `ENCLAVE_APP=zing-watermark` 是否正確
3. 查看構建日誌中的錯誤信息
4. 確認所有依賴都已安裝

## 權限檢查清單

- [ ] AWS IAM Role `github-actions-cicd-role` 存在
- [ ] OIDC Provider 已配置
- [ ] IAM Role 信任策略包含倉庫
- [ ] IAM Role 有 S3 權限
- [ ] IAM Role 有 Terraform backend 權限（如果啟用 auto-apply）
- [ ] S3 buckets 已創建
- [ ] Terraform backend 已配置
- [ ] GitHub Actions 已啟用
- [ ] 倉庫有 `pull-requests: write` 權限
- [ ] `zing-infra` 倉庫可訪問

## 下一步

設置完成後，可以：

1. **測試自動部署**: 推送代碼到 `main` 分支
2. **手動部署**: 使用 workflow_dispatch 觸發
3. **監控部署**: 查看 Actions 頁面和 CloudWatch 日誌

## 相關文檔

- [Workflow README](./README.md)
- [Terraform Enclave Module](../../../zing-infra/modules/aws/enclave/README.md)
- [GitHub CICD Module](../../../zing-infra/modules/aws/github-cicd/README.md)

