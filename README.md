# secret-leak-local

[![CI](https://github.com/niuxinhuai/secret-leak-local/actions/workflows/ci.yml/badge.svg)](https://github.com/niuxinhuai/secret-leak-local/actions/workflows/ci.yml)

Scan local files for common secret, token, private key, and .env leakage patterns before committing.

提交前扫描本地文件中常见的 secret、token、私钥和 .env 泄露风险。

## English

### Install

```bash
npm install -g secret-leak-local
```

For local development:

```bash
npm install
npm link
secret-leak-local --help
```

### Features

- Scans paths or staged files.
- Detects private keys, AWS keys, GitHub tokens, Slack tokens, JWTs, and env-style secrets.
- Masks detected values in output.
- Supports allow patterns through .secretignore and exits 2 when findings exist.

### Usage

```bash
secret-leak-local .
secret-leak-local --staged
secret-leak-local src config --json
secret-leak-local . --allow-file .secretignore
```

### Automation

Use `secret-leak-local --staged` in pre-commit hooks and full path scans in CI.

### Test

```bash
npm test
npm --cache /tmp/npm-cache pack --dry-run .
```

## 中文

### 安装

```bash
npm install -g secret-leak-local
```

本地开发：

```bash
npm install
npm link
secret-leak-local --help
```

### 功能

- 支持扫描路径或 staged 文件。
- 识别私钥、AWS key、GitHub token、Slack token、JWT 和 env 风格 secret。
- 输出中会遮蔽敏感值。
- 支持 .secretignore 允许列表；发现风险时退出码为 2。

### 用法

```bash
secret-leak-local .
secret-leak-local --staged
secret-leak-local src config --json
secret-leak-local . --allow-file .secretignore
```

### 自动化

Use `secret-leak-local --staged` in pre-commit hooks and full path scans in CI.

### 测试

```bash
npm test
npm --cache /tmp/npm-cache pack --dry-run .
```
