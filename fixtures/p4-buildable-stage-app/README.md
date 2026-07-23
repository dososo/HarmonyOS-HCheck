# 非生产 Stage 构建回归样例

本工程用于 HCheck 的 Stage/HAP 构建与软件包读取回归测试。它不连接网络、不申请权限、不使用账号、不包含第三方依赖，也不包含生产签名配置。

执行时需要安装兼容的 DevEco Studio、HarmonyOS SDK 与 Hvigor。请按本机官方安装说明设置 SDK 根目录与工具路径，例如：

```bash
export DEVECO_SDK_HOME="/Applications/DevEco-Studio.app/Contents/sdk"
export PATH="/Applications/DevEco-Studio.app/Contents/tools/ohpm/bin:/Applications/DevEco-Studio.app/Contents/tools/hvigor/bin:$PATH"
```

然后在本目录执行：

```bash
./hvigorw --version
./hvigorw clean assembleHap --mode module -p product=default -p buildMode=release --no-daemon
```

`DEVECO_SDK_HOME` 应指向 SDK 根目录。工程根的 `hvigorw` 只委托 `PATH` 中已安装的 DevEco Hvigor，不下载或复制工具。未配置签名时，产物仅用于本地构建、哈希和只读检查，不能用于安装、提交商店或生产发布。

`.hvigor/`、`oh_modules/` 和 `build/` 等生成目录不得提交。
