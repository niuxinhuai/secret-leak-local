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

### Usage

Scan a path.

```bash
secret-leak-local .
secret-leak-local src config --json
```

### Status

This is an MVP designed to be useful immediately and easy to extend. It has no runtime dependencies and targets Node.js 18+.

### Test

```bash
npm test
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

### 用法

扫描一个或多个路径。

```bash
secret-leak-local .
secret-leak-local src config --json
```

### 当前状态

这是一个可以直接使用的 MVP，重点是小、清晰、容易二次开发。运行时无第三方依赖，要求 Node.js 18+。

### 测试

```bash
npm test
```
