# MCP Armor Easy UI

轻量档位界面：AST 与字节码独立调节，网易模式/原生模式，以及多文件夹/单个 PY 输入。

启动时会居中显示 `assets/Logo.png` 无边框加载画面 3 秒；较小屏幕自动等比例缩小，随后切换到主界面。

Splash 显示期间会并行执行 HWID 授权验证。验证通过后进入主界面；未授权、到期、Gitee 授权服务器或淘宝时间 API 异常时显示具体原因和 HWID，自动复制 HWID 后结束 Easy UI。运行混淆时 CLI 后端仍会再次验证。

## 档位

AST：关闭、低强度、中强度、高强度。可选 Rename、字符串 XOR/分割、调用链拆分、常量池、轻量噪声和 AST VM。低档关闭 VM；中档默认虚拟化约 12%；高档约 28%，并限制函数规模与数量以控制启动性能。VM 已支持闭包/嵌套函数、lambda、with、try/finally、生成器（按排除规则跳过热路径）；界面可直接调整 VM 比例；完整 VM 与实验性反调试仍不进入 Easy UI。

字节码层始终开启，只有低/中/高三个档位：

| 档位 | ByteCode_Flow 与结构 |
| --- | --- |
| 低强度 | CFG 25%，最多 2 条边；栈等价噪声、条件跳转反转；低密度 JMP 花指令和 oparg 错位 |
| 中强度 | CFG 50%，块种子 35%；双段跳板、不透明谓词、冷函数诱饵岛、分片和引用表 |
| 高强度 | CFG 75%，块种子/块重排；实块重排、索引池洗牌、延迟常量、槽位幻象和多层跳板 |

“JMP 花指令”由 taken-jump poison 实现：跳转落到可跳过的非法 opcode 行；`oparg_poison` 同时写入错位/越界操作数。密度在档位中递增，便于在性能和强度间选择。

界面会直接显示 ByteCode_Flow 密度滑块、最大边数、块种子、块重排和循环分发选项；JMP 花指令与 oparg 错位固定开启。

网易模式使用 cPickle loader 与 V1 opcode 映射；原生模式仍保留字节码 loader，但使用标准 opcode/function loader，不启用网易映射。

## 排除与 AntiDebug

- “附加排除”支持逗号、分号或换行分隔，可填写 `importer.py`、`ui/*.py` 等路径模式；内置的 `modMain.py`、`config.py`、`__init__.py` 排除仍保留。
- 网易模式可开启 `AntiDebug（原生 _chacha + manifest UUID）`，它会启用 ChaCha payload，并将解密绑定到网易原生 `_chacha` 行为和最近行为包 `manifest.json` 的 `header.uuid`。
- 开始运行前会校验 manifest UUID；原生模式自动关闭该项。

## 启动

```text
python -m MCP_Armor_Easy_UI
```

运行配置写入 `%LOCALAPPDATA%\\MCPArmor\\easy_run_config.yml`。
“Python 2.7” 可选择解释器的 `python.exe`；路径会写入配置的
`runtime.python27`，下次启动会自动恢复。

“构建前静态检查”默认关闭，调试期间可跳过网易模块白名单检查；
正式构建前勾选后，配置中的 `static_check.enabled` 会恢复为 `true`。

## 冒烟测试

```text
python tests\\run_easy_ui_profiles.py
python tests\\run_easy_ui_profile_obfuscation.py
```

## 本地 HWID 策略（`isFree`）

程序启动时会优先读取可执行文件旁的 `i.txt`/`hwid.json`；也可以通过
`MCPARMOR_HWID_FILE` 指定策略文件。策略中的顶层 `isFree` 控制授权路径：

```json
{ "isFree": true, "hwid": {} }
```

`isFree: true` 直接进入免费模式，不采集或校验 HWID，也不请求网络时间；
`isFree: false`（或缺失）继续执行 HWID 表和到期时间检查。CLI、Full UI、
Easy UI 使用同一套策略。Nuitka 发布目录会自动复制 `i.txt`，无需重新编译即可
更新策略。\n