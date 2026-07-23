# 非生产四产物 Stage 回归样例

本工程用于 HCheck 的 APP、HAP、HSP、HAR 构建与读取回归测试。它不是产品工程模板，不得安装、上架或用于生产发布。

工程不申请权限、不访问网络、不使用账号、不包含第三方依赖，也不包含生产签名配置。`entry`、`shared`、`har` 三个模块彼此没有依赖；其中 `entry` 生成 HAP，`shared` 生成 HSP，`har` 生成 HAR，项目级任务生成包含 HAP 与 HSP 的 APP。

运行前应由调用方把 DevEco Studio 自带的 ohpm 与 Hvigor 加入 `PATH`，并把 `DEVECO_SDK_HOME` 指向 DevEco Studio 的 SDK 根目录。工程根的 `hvigorw` 只委托当前 `PATH` 中的 DevEco Hvigor，不下载或复制工具。

在本目录依次执行：

```bash
./hvigorw clean --no-daemon
./hvigorw assembleHap --mode module -p module=entry@default -p product=default -p buildMode=release --no-daemon
./hvigorw assembleHsp --mode module -p module=shared@default -p product=default -p buildMode=release --no-daemon
./hvigorw assembleHar --mode module -p module=har@default -p product=default -p buildMode=release --no-daemon
./hvigorw assembleApp --mode project -p product=default -p buildMode=release --no-daemon
```

只允许把无签名产物用于只读验收。`.hvigor/`、`oh_modules/`、各级 `build/`、`local.properties` 和真实二进制产物均不得提交。
