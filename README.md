# ka_quic_kill —— 强制快手关闭 QUIC

## 为什么需要它

快手 14.10.30.51353 的网络层 `com.kuaishou.aegon.Aegon` 默认开启 QUIC，
登录接口（`mobileQuick`）实际走 `http/2+quic/43` 到 `[2408:8726:…]:8443`。

原来那个模块 hook 的是 `Aegon.nativeUpdateConfig` —— **这个方法在 14.10 里不存在**，
`findAndHookMethod` 直接抛异常，所以 QUIC 一直没被降级（真机日志里仍是 `ssl_version: QUIC`）。

## 本模块 hook 的三个真实入口（已在 14.10.30.51353 验证存在）

| 目标 | 签名 | 作用 |
|---|---|---|
| `Aegon#nativeSetGlobalConfig` | `(String jsonConfig, String storagePath, boolean)` | 初始化时传的配置 JSON，注入 `enable_quic:false` |
| `Aegon#k` | `(Map)` | Java 层配置入口，`key=0` 是配置 JSON |
| `Aegon#nativeSetQuicFallbackToTcpBlacklist` | `(String[])` | 直接把网关 host 拉进 QUIC→TCP 回落黑名单 |

注入内容：

```json
{ "enable_quic": false,
  "quic_host_blacklist": [".ksapisrv.com", ".az1-api.ksapisrv.com", ...],
  "altsvc_broken_time_max": 86400,
  "altsvc_broken_time_base": 86400 }
```

## 编译

本地没有 Android SDK 时用 GitHub Actions：

```bash
git init && git add -A && git commit -m init
git remote add origin <your repo>
git push -u origin main
```

Actions 跑完在 Artifacts 里下 `ka_quic_kill-apk`。

## 验证是否生效

装好后在 LSPosed 里勾选「快手」，重启快手，然后看 App 自己的日志：

```bash
adb shell "su -c 'cat \$(ls -t /data/data/com.smile.gifmaker/files/debuglog/app/main/*.log | head -1)'" | grep -o '\"protocol\":\"[^\"]*\"'
```

- 生效 → `"protocol":"http/1.1"`
- 没生效 → `"protocol":"http/2+quic/43"`

同时 `adb logcat -s QUICK` 会打印每次 hook 命中。
