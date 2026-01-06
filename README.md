# 复旦大学成绩自动监控与推送 (Fudan Grades Monitor)

这是一个基于 Python 和 GitHub Actions 的自动化工具，用于定时抓取复旦大学（fdjwgl.fudan.edu.cn）的个人成绩，并在出分或绩点变化时自动发送邮件通知。

## 核心功能

*   **自动抓取**: 模拟登录复旦教务系统，自动处理复杂的重定向和身份验证（UIS RSA 加密）。
*   **GPA 计算**: 自动获取课程学分，计算每学期 GPA 和累计 GPA。
    *   **注意**: 按照要求，等级为 **P (Pass)** 或 **NP (No Pass)** 的课程**不计入** GPA 计算。
*   **隐私安全**:
    *   你的成绩数据会被保存为 `grades_encrypted.json`。
    *   **加密存储**: 使用你的 UIS 密码派生出的密钥进行高强度加密（AES），即使文件公开，没有你的密码也无法解密。
    *   敏感信息（学号、密码、邮箱授权码）均通过 GitHub Secrets 注入，不直接出现在代码中。
*   **邮件推送**:
    *   一旦检测到新成绩或成绩更新，立即向你的复旦学邮（`学号@m.fudan.edu.cn`）发送通知。
    *   邮件主题会区分“好消息”（GPA上升）、“坏消息”（GPA下降）或普通更新。
*   **无人值守**: 部署在 GitHub Actions 上，每小时自动运行一次，无需本地挂机。

## 技术流程原理

1.  **环境初始化**: GitHub Actions 启动 Ubuntu 容器，安装 Python 依赖（`requests`, `pycryptodome`, `cryptography`）。
2.  **模拟登录**:
    *   脚本读取环境变量中的学号和密码。
    *   请求 `id.fudan.edu.cn` 获取公钥，使用 RSA 加密密码。
    *   完成 UIS 统一身份认证，获取 Session Cookies。
3.  **数据抓取**:
    *   动态探测个人的成绩单 ID。
    *   请求成绩 API 和课程详情 API（获取学分）。
4.  **数据处理**:
    *   计算当前 GPA（过滤掉 P/NP 课程）。
    *   尝试读取并解密旧的 `grades_encrypted.json`（如果存在）。
    *   对比新旧数据，找出新增或变动的课程。
5.  **通知与存储**:
    *   如果有变化，通过 QQ 邮箱 SMTP 服务发送格式化邮件。
    *   将最新的成绩数据加密后覆盖保存到 `grades_encrypted.json`，并提交回 GitHub 仓库，供下一次运行时对比使用。

## 使用指南 (How to Use)

只需简单几步，你就可以拥有自己的成绩监控机器人。

### 1. Fork 本仓库
点击页面右上角的 **Fork** 按钮，将本项目复制到你的 GitHub 账号下。

### 2. 配置 GitHub Secrets
为了保护你的隐私，所有敏感数据都必须配置在 Secrets 中。
进入你 Fork 后的仓库，点击 **Settings** -> **Secrets and variables** -> **Actions** -> **New repository secret**，添加以下 4 个变量：

| Secret Name | 说明 | 示例值 |
| :--- | :--- | :--- |
| `STUDENT_ID` | 你的复旦学号 | `23300123456` |
| `UIS_PASSWORD` | 你的 UIS 登录密码 | `MySecretPass123` |
| `QQ_EMAIL_SENDER` | 发送通知的 QQ 邮箱地址 | `12345678@qq.com` |
| `QQ_SMTP_AUTH_CODE` | QQ 邮箱的 SMTP 授权码* | `abcdefghijklmnop` |

> **如何获取 QQ SMTP 授权码**:
> 登录 QQ 邮箱网页版 -> 设置 -> 账号 -> 向下滚动找到 "POP3/IMAP/SMTP/Exchange/CardDAV/CalDAV服务" -> 开启服务 -> 生成授权码。

### 3. 启动监测
配置完成后，GitHub Actions 默认会按照计划（每小时）自动运行。
你可以手动触发第一次运行来初始化数据：
1.  点击仓库上方的 **Actions** 标签。
2.  在左侧选择 **Fudan Grades Monitor**。
3.  点击右侧的 **Run workflow** 按钮 -> **Run workflow**。

### 4. 运行结果
*   **第一次运行**: 会抓取当前所有成绩并加密保存。因为没有旧数据对比，**不会**发送邮件。
*   **后续运行**: 每小时自动检查。如果有新成绩（例如期末周出分），你会收到邮件通知。

## 免责声明
本项目仅供学习交流使用。请勿用于非法用途或高频恶意请求学校服务器。使用本工具产生的任何后果由使用者自行承担。
