[English](/README.md) | [中文](/README_zh-CN.md)

<h1 align="center">VPS Studio</h1>

<div align="center">
  <strong>一款现代化、高性能、纯本地的跨平台服务器管理与 SSH 客户端。</strong>
</div>
<br>

<div align="center">
  <img src="https://img.shields.io/badge/Platform-Windows-blue?style=flat-square" alt="Platform: Windows" />
  <img src="https://img.shields.io/badge/Framework-Tauri-ffc131?style=flat-square" alt="Framework: Tauri" />
  <img src="https://img.shields.io/badge/Language-Rust%20%26%20JavaScript-orange?style=flat-square" alt="Language: Rust/JS" />
  <img src="https://img.shields.io/badge/License-Proprietary-red?style=flat-square" alt="License" />
</div>

<br>

## 📢 最新更新 (What's New)

*当前为 `v0.2.0` 初版发布，尚未有历史更新。以后新版本的更新日志、修复细节及新增功能将记录于此。*

<br>

## 🚀 为什么选择 VPS Studio？ (核心优势)

传统的 SSH 工具（如 Xshell、Putty）往往界面陈旧，而一些现代工具（如 Termius）又依赖于云端同步，对于重视隐私的极客和开发者而言，安全性始终是个顾虑。

**VPS Studio** 应运而生，它旨在提供**极致现代化的用户体验**，同时**完全由你掌控自己的数据**：

- 🔒 **纯本地数据存储**：无需注册账号，不依赖任何云服务，你的所有服务器配置、SSH 密钥（Key）和密码都通过 WebView2 安全地持久化在你自己的电脑本地硬盘中，真正的隐私安全。
- ⚡ **极致轻量且高性能**：由 **Rust** 结合 Tauri 构建后端，内存占用低，启动如丝般顺滑。
- 🔑 **全能密钥与身份管理**：内置强大的本地密钥库，支持一键生成现代化的 `Ed25519` 或 `RSA`、`ECDSA` 密钥，并且支持将一个身份（包含账户和凭据）快捷分配给多个主机，管理几十台服务器也能井井有条。
- 💡 **一键代码片段 (Snippets)**：内置代码片段库，只需点击一下即可向目标服务器批量发送复杂指令，告别重复的敲键盘。
- 🇨🇳 **原生沉浸式中文支持**：为国内开发者深度定制，全界面精校汉化，消除语言壁垒。
- 💻 **内置本地终端集成**：无需切换应用，在主界面中一键呼出本地 PowerShell，直接进行本地环境操作。

## 📦 安装说明

VPS Studio 提供了极其灵活的使用方式，满足不同用户群体的使用习惯。你可以在 Releases 页面中找到以下两个版本：

### 1. 便携版 (Portable)
下载 `vps-studio.exe`。
**使用方法**：直接双击运行！完全绿色免安装。无需配置环境，你可以把它放在桌面上，甚至放进 U 盘里随身携带。只要是在现代的 Windows 10/11 系统（已内置 Microsoft Edge WebView2）下均可直接启动。

### 2. 传统安装包版 (Installer)
下载 `VPSStudioSetup.exe`。
**使用方法**：双击运行安装向导，它会自动在系统控制面板中注册，并能在桌面上生成快捷方式。如果你需要卸载，只需在控制面板中点击卸载，或者运行其自带的卸载程序（`unins000.exe`）即可干净无痕地移除。

## 📖 快速上手指南

1. **管理你的凭据**：点击侧边栏进入**保管库 (Keychain)**，你可以直接新建并生成一个 `Ed25519` 密钥，或者通过拖放文件的方式导入你现有的私钥文件。
2. **定义身份 (Identity)**：将你在保管库中的密钥或密码与登录用户名（例如 `root`）绑定成一个“身份”。
3. **添加主机 (Host)**：在主机列表页点击新建，输入你的服务器 IP，并在下拉菜单中直接选中你刚刚创建的“身份”。
4. **一键连接**：双击你刚刚添加的服务器卡片，或者右键选择连接，即可瞬间唤出终端进入管理状态！

## 👨‍💻 技术栈

- **Frontend**: HTML5, Vanilla JavaScript, CSS3
- **Backend / Core**: Rust, Tauri
- **Terminal Emulator**: xterm.js (集成)
- **Installer Engine**: Inno Setup

---
<div align="center">
  <b>Copyright &copy; 2026 Caesars Network LLC. All rights reserved.</b>
</div>
