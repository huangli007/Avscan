# avscan — 多引擎批量扫毒工具

把一个安装包 / 安装目录丢给 9 款杀软批量扫，输出一份可以直接贴进测试报告的**扫毒证据链**。

零第三方依赖，纯 Python 标准库，Windows 下即装即用。

> 核心引擎（`avscan/`）只用标准库。图形界面额外需要 `PySide6` 与 `uiautomation`（均 MIT 协议），
> 打包版已内置；源码运行时 `pip install PySide6 uiautomation`。

> **下载可执行版**：[Releases](https://github.com/huangli007/Avscan/releases) — `avscan-v1.0.0-win64.zip`，解压即用，无需装 Python。
>
> **文档导航**：[FEATURES.md](FEATURES.md) 功能清单 · [ARCHITECTURE.md](ARCHITECTURE.md) 架构设计

---

## 扫描证据截图

扫描完成后自动生成 `runs/<run_id>/screenshots/`：

| 文件 | 内容 |
|---|---|
| `<引擎key>.png` | 该引擎的**原始输出**渲染成的终端风格截图（带行号、标题、退出码） |
| `overview.png` | 结果表总览（结论徽章 + 各引擎状态） |

`report.md` 直接引用这些图。

**「无毒」结论必须有截图。** 缺截图的引擎会被降级为「未取得结论」，
总评因此不会判通过 —— 只有结论没有证据，等于没扫。

命令行引擎没有界面，它的「截图」就是把 stdout/stderr 渲染成图，这才是它真正的证据。
仅 GUI 引擎（火绒等）没有命令行输出，把它的界面截图**手动存为
`screenshots/huorong.png`**（文件名 = 引擎 key），报告会自动引用，不需要改任何代码。

> 结果截图是自动生成的，但引擎界面的截图得你自己截一下。
> 点结果行的「定位」打开目标 → 切到杀软窗口截屏 → 存成 `screenshots/<引擎key>.png`。

## 图形界面

```bash
python scan.py gui
```

PySide6 实现，Notion 极简风格：白底、1px 细线分隔、无阴影渐变、13px 正文、大量留白。
流程压成一条线，三个页面：

| 页面 | 内容 |
|---|---|
| **扫描** | 拖入目标 → 勾选引擎 → 开始扫描 → 结果自动滚到眼前，一屏走完 |
| **安装包** | 归档清单表格，选中行后可「一键安装」（静默参数已备）或「打开文件夹」手动装 |
| **历史** | 本地运行记录，点选可直接打开对应报告 |

**扫描目标支持文件与文件夹混合**：点一下拖拽区会给出「选择文件」和「选择文件夹」两个入口；
拖进来的目录会立即统计出文件数与总体积，扫描时交由引擎自身递归遍历（不逐文件启动引擎，速度快一个量级）。

**扫描范围两档**，默认全量：

| 模式 | 行为 | 适用 |
|---|---|---|
| **全量**（默认） | 整个目录一次性交给引擎递归 | 发布前普扫，最快 |
| **仅扫高危文件** | 只挑 exe/dll/脚本/压缩包，逐个送检 | 想精确定位到具体文件时 |

勾选「仅扫高危文件」后界面会先算出待检文件数——因为它是**逐文件**送检，每个文件都要单独启动一次引擎，
几千个文件就是几千次启动。数量偏多时提示里会直接建议改回全量。

扫描与引擎探测都在后台线程执行，界面不阻塞；扫描中可取消，取消后已完成的结果照样落盘出报告。

**标识**：圆角深底 + 双层环 + 中心蓝点，外环留 90° 缺口表示「扫描进行中」。
16–24px 自动退化为「单环+点」避免糊成一团。改配色或比例后跑 `python gui/_logo.py` 重新生成全套尺寸。

### 右键一键扫描

```bash
python scan.py shell install    # 注册右键菜单（写入 HKCU，不需要管理员）
python scan.py shell status     # 查看注册状态与指向的程序
python scan.py shell uninstall  # 随时撤销
```

注册后在资源管理器里右键 **任意文件 / 任意文件夹 / 文件夹空白处**，都会出现「用 avscan 扫描」，
点击即启动程序、自动加入目标并开扫，不用再手动拖入。

实现方式是注册表静态动词（`%1` / `%V`），**不写 Shell 扩展 DLL**——后者要编译 C++，一旦崩溃会拖垮整个资源管理器。

### 引擎启动路径可改

引擎装在非标准目录、或有多个副本导致探测到错的那个时，可以在引擎行点「路径」手动指定 exe。
指定后该引擎跳过自动探测，行上会标「手动指定」；再点一次可以「恢复自动探测」。

配置存在 `config/engines.json`（程序目录不可写时退回 `%APPDATA%\avscan\config`）：

```json
{ "overrides": { "stinger": "D:\\tools\\stinger64.exe" } }
```

指定了无效路径会明确报「手动指定的路径不存在」，而不是悄悄回退自动探测——后者会让人以为改了没生效。

### 仅 GUI 的引擎怎么办（火绒 / 360 / 腾讯管家）

这三款**无法程序化驱动**，不是没试，是四条硬障碍（对本机火绒实测）：

| 探测项 | 结果 |
|---|---|
| 命令行接口 | 只有内部 C++ 符号（`CreateScanTask` / `SCANTYPE_custom`），无 CLI 开关 |
| 右键扫描动词 | 由 `hrdevmon.sys` + `hrwfpdrv.sys` 内核驱动注入 explorer 动态生成，注册表无痕 |
| 启动主程序 | 脚本 `CreateProcess` 被拒，`WinError 5`（自我保护，仅放行管理员） |
| 扫描日志 | `HipsMain.log` 加密，无法解析结论 |

**策略：引擎自己的右键扫描是第一选择。**

点结果行右侧的「模拟右键」，程序会做和人工完全一样的动作：

```
explorer /select 选中目标 → 激活窗口 → Shift+F10 打开上下文菜单
→ 在菜单里找到该引擎的扫描项 → 用 UIA 的 InvokePattern 触发
```

**不移动鼠标、不抢光标**，只在几秒内借用一次前台焦点。

实测结果：

| 引擎 | 模拟右键 | 说明 |
|---|---|---|
| Malwarebytes | ✅ 可用 | 菜单项「用 Malwarebytes 扫描」能被触发 |
| 火绒 | ❌ 无效 | 程序触发的右键里**根本没有它那一项**（菜单像素图已确认） |

火绒不响应程序化点击，所以走双轨：**模拟右键 → 失败自动回退到它的私有协议**
（`HipsMain.exe -S <清单>`，需管理员权限）→ 再失败才提示人工。

> 顺带说明：火绒的菜单项不是标准 IContextMenu 扩展注入的，
> 鼠标轨迹、键盘菜单、程序化点击三种方式都试过，均不出现该菜单项。

扫完回到结果行点「回填」，选「未发现威胁 / 发现威胁 / 跳过」并填写备注，
自动写 `manual_results.json` 并重算报告。

> 火绒额外提供「触发」按钮直接走私有协议，绕过模拟右键这一层。

### 建议全程用管理员身份运行

两个引擎都卡在权限上，一起解决：

| 引擎 | 非管理员的表现 | 管理员下 |
|---|---|---|
| McAfee Stinger | `WinError 740` 启动失败 | 正常扫描 |
| 火绒 | 触发被拒（`WinError 5`） | 扫描窗口正常拉起 |
| Windows Defender | 正常（MPCmdRun 不需要提权） | 正常 |

永久生效的办法：右键 `avscan.exe` → 属性 → 兼容性 → 勾选「以管理员身份运行此程序」，
之后每次双击都会请求一次 UAC，不再需要手动右键。

> 开发时可用 `python gui/_shot.py` 离屏截三张页面图自查样式，输出到 `.workbuddy/tmp/shots/`。

---

## 打包分发

```bash
python -m PyInstaller --noconfirm --clean --windowed --name avscan --onedir \
  --add-data "packages/manifest.json;packages" \
  --exclude-module PySide6.QtWebEngineCore --exclude-module PySide6.QtWebEngineWidgets \
  --exclude-module PySide6.Qt3DCore --exclude-module PySide6.QtMultimedia \
  --exclude-module PySide6.QtQuick --exclude-module PySide6.QtQml \
  --exclude-module PySide6.QtCharts --exclude-module PySide6.QtDataVisualization \
  app.py
```

产物 `dist/avscan/`，约 **118 MB**（exe 本体 1.9 MB，其余是 Qt 运行库）。
用 `--onedir` 而非 `--onefile`：onefile 每次启动都要解压到临时目录，冷启动慢一倍以上，且更容易被杀软误判为自解压壳。

**目录约定（重要）**

数据目录一律以 **exe 所在目录**为准，不是打包内部目录：

```
dist\avscan\
├── avscan.exe
├── _internal\          # 运行库 + 内置 manifest
├── tools\              # ← 可选：复制项目 tools/ 过来，便携扫描器才可用
├── packages\           # ← 可选：复制项目 packages/ 过来，安装包页才有内容
└── runs\               # 扫描记录（自动生成）
```

不放 `tools/` 也能运行，只是少几个引擎——界面会在引擎区明确提示「未找到 tools/ 目录」并给出应该放哪里，而不是让人对着一排「未安装」发懵。

**注意事项**

- 首次运行 Windows 可能弹 SmartScreen，需「更多信息 → 仍要运行」（未做代码签名）；
- exe 是 windowed 无控制台，**CLI 功能仍需 `python scan.py`**；
- 部分引擎（Stinger）要求管理员权限，否则会判为 `error`。

---

---

## 一、先说清楚：9 款引擎的真实能力边界

这是本工具最重要的部分。**不是所有杀软都能命令行调用**，假装都能自动化只会产出一份假报告。

| # | 引擎 | 命令行接口 | 自动化 | 说明 |
|---|---|---|---|---|
| 1 | 火绒安全软件 | ❌ 无 | 人工 | 扫描入口只在 GUI：「病毒查杀 → 自定义查杀」 |
| 2 | 360 安全卫士 / 360 杀毒 | ❌ 无 | 人工 | 无对外公开的命令行扫描协议 |
| 3 | 腾讯电脑管家 | ❌ 无 | 人工 | 同上 |
| 4 | Avira | `avscan.exe` | 自动 | 参数随版本变动，建议先 `--dry-run` |
| 5 | Malwarebytes | `mbam.exe` | 受限 | **仅商业版**支持定向路径扫描，免费版只能人工 |
| 6 | McAfee Stinger | `stinger.exe` | 自动 | 绿色按需扫描器，最适合与其它杀软并存 |
| 7 | 卡巴斯基 | `avp.com` | 自动 | 若设了管理密码需追加 `/password:<pwd>` |
| 8 | Avast | `ashCmd.exe` | 自动 | 新版可能已移除该组件，探测不到请走人工 |
| 9 | Windows Defender | `MpCmdRun.exe` | 自动 | 最稳定的一条基线 |

所以工具输出分三类结论：**✅ 无毒 / ❌ 检出 / ⚠️ 未取得结论**。
被跳过的、超时的、读不懂输出的，一律不计入「无毒」——这是扫毒报告的底线。

> 火绒、360、腾讯管家三家为什么没有 CLI：它们把扫描做成 GUI 交互流程，没有对外暴露
> 可脚本化的扫描协议。绕过去的唯一办法是 UI 自动化（模拟点击），既脆弱又没法作为
> 发布证据，所以这里不采用，改为「生成核对单 + 人工回填 + 自动合并」。

---

## 二、快速开始

```bash
cd C:\Users\TianManyi\WorkBuddy\scan

# 1. 看这台机器上装了哪些引擎、哪些能自动跑
python scan.py detect

# 2. 演练：只打印将执行的命令，不真扫
python scan.py scan "D:\pkg\CTONE_Setup.exe" "D:\pkg\CTONE" --dry-run

# 3. 正式扫（安装包 + 安装目录一起）
python scan.py scan "D:\pkg\CTONE_Setup.exe" "D:\pkg\CTONE" --label "CTONE V0.5.8 发布包"
```

扫完会在 `runs/RUN-YYYYMMDD-HHMMSS-<label>/` 下产出：

| 文件 | 用途 |
|---|---|
| `report.md` | 主报告，直接贴进测试报告 |
| `report.csv` | Excel 可直接打开（UTF-8 BOM，中文不乱码） |
| `report.json` | 机器可读，供 CI 或二次统计 |
| `manual-checklist.md` | 无 CLI 引擎的人工核对单 |
| `raw/` | 每个引擎的原始 stdout/stderr，**证据留档** |
| `meta.json` / `results.json` | 本次运行的完整快照 |

---

## 三、命令

### `detect` — 环境探测

```bash
python scan.py detect
python scan.py detect --json          # 机器可读
```

输出每个引擎的：是否安装、可否自动跑、产品版本、病毒库版本、病毒库日期、可执行文件路径。
自动扫描所有盘符的 `Program Files`，并从注册表卸载项反查真实安装路径（国产安全软件常装在 D 盘）。

### `scan` — 批量扫描

```bash
python scan.py scan <目标...> [选项]
```

| 选项 | 说明 |
|---|---|
| `--engines` | `auto`（默认，只跑有 CLI 的）/ `all` / `manual` / `defender,kaspersky` |
| `--label` | 任务标签，会写进运行目录名和报告 |
| `--timeout` | 单引擎单目标超时秒数，默认 1800 |
| `--per-file` | 逐文件扫描（慢，用于精确定位是哪个文件） |
| `--only-risk` | 只扫高危扩展名（exe/dll/sys/ps1/zip/msi…），隐含 `--per-file` |
| `--dry-run` | 只打印命令不执行，**首次使用某引擎必跑** |
| `--yes` | 跳过确认 |
| `--out` | 结果根目录，默认 `./runs` |

扫描目标可以是多个文件、多个目录，或混合。

### `report` — 重新出报告

```bash
python scan.py report runs/RUN-20261029-152412-merge-test
```

用途：人工扫描完回填 `manual_results.json` 之后，重新生成报告把人工结论合并进来。

### `merge` — 合并多次运行

```bash
python scan.py merge runs/RUN-A runs/RUN-B runs/RUN-C --label "CTONE 发布包"
```

用于「装一款杀软 → 扫 → 卸载 → 换下一款」的现实场景，把分次结果收成一份总报告。
同一引擎出现多次时取**最严重**的结论（保守优先），并标注来源 run。

### `selftest` — 解析器自检

```bash
python scan.py selftest
python scan.py selftest -V      # 打印每个样本的判定说明
```

用 13 个构造样本验证解析器：该判检出时必须判检出，读不懂时必须判**未知**。
这条是防止工具退化成「永远返回无毒」——那种工具比没有工具更危险。

### `inspect` — 安装包静态体检

```bash
python scan.py inspect "E:\share\scan" --md "体检报告.md"
```

**只读文件，不执行、不解压、不调安装程序。** 用于回答：这批包是不是正版、有没有被捆绑、该用什么静默参数、有没有加壳。

输出 PE 结构（位数/子系统/.NET/节区）、编译时间、安装框架（NSIS/Inno/InstallShield/MSI/SFX）、加壳判定、签名与签发者、SHA256 与 VirusTotal 哈希直链。

两个判定原则值得留意：

- **加壳只认 PE 节名**（`UPX0`/`.vmp0`/`.themida`/`.MPRESS` 等）。大文件里搜到 `UPX!` 字符串往往是内嵌组件的正常引用，据此判加壳会误报——实测中卡巴 189 MB 的包就因此被误判过一次。
- **PE 时间戳不可尽信**。链接器会给默认值，也可能被刻意改写。异常年份（如 1970、2005）会明确标注出来。

### `packages` — 安装包仓库（一键安装 / 手动安装）

带实时防护的杀软没法绿色化，只能安装。所以把安装包归档进 `packages/`，由清单描述"能不能一键静默装"。

```bash
python scan.py packages list                  # 有哪些包、哪种安装方式
python scan.py packages install huorong       # dry-run：只打印命令和风险
python scan.py packages install huorong --yes # 真装
python scan.py packages open kaspersky        # 无静默参数 → 打开文件夹手动装
python scan.py packages verify                # 重新校验签名，确认包没被换过
```

三种安装方式：

| 方式 | 含义 |
|---|---|
| **一键安装** | 清单里有可靠静默参数，可无人值守 |
| **一键安装\*** | 参数格式正确但**未经本机实测**，首次建议先手动确认 |
| **手动安装** | 无静默参数，只提供「打开文件夹」定位 |
| **免安装** | 便携扫描器，直接运行 exe |

`install` 默认 **dry-run**，必须加 `--yes` 才执行——装杀软会写内核驱动、改系统、要求重启。

**当前离线包覆盖情况**

| 引擎 | 安装包 | 能否离线部署 |
|---|---|---|
| 火绒 6.0.11.1 | 离线 66MB · NSIS | ✅ 可一键（`/S`） |
| 360 杀毒 7.0.0.1070A | 离线 58MB | ✅ 可离线，静默参数未验证 |
| 卡巴斯基 KTS 21.3.10.391 | 离线 189MB | ✅ 可离线，静默参数未验证 |
| Malwarebytes 4.2.3.199 | 离线 189MB | ✅ 可离线（内嵌 MSI，可解出后 `msiexec /qn`） |
| **Avast** | 在线 1.7MB | ⚠️ 需联网下载主体 |
| **Avira** | 在线 6.5MB | ⚠️ 需联网下载主体 |
| **腾讯电脑管家** | 在线 12MB | ⚠️ 需联网下载主体 |
| **360 安全卫士** | 在线 1MB | ⚠️ 需联网下载主体 |
| McAfee 杀毒主体 | **无** | ❌ 只有 Stinger 专杀工具 |
| Windows Defender | 系统自带 | — 无需安装包 |

在线安装器要在有网环境先跑一次、把主体下下来，才能在离线机器上部署。

---

## 四、人工引擎怎么补

1. 打开运行目录下的 `manual-checklist.md`，里面列了待扫引擎和扫描目标；
2. 按提示在杀软 GUI 里做**自定义查杀**（⚠️ 不要勾「自动清理」，先只检测）；
3. 记下结果，填进同目录的 `manual_results.json`：

```json
{
  "huorong": {
    "status": "clean",
    "db_version": "2026.10.29.1",
    "db_date": "2026-10-29",
    "note": "GUI 自定义查杀完成，0 威胁"
  },
  "360": {
    "status": "clean",
    "db_version": "",
    "db_date": "",
    "note": ""
  }
}
```

`status` 取值：`clean` / `infected` / `error`。

4. 重新出报告：

```bash
python scan.py report runs/RUN-20261029-152412-merge-test
```

结论会自动从「待补」变成「通过」或「不通过」。

---

## 五、⚠️ 重要：不要把 9 款杀软同时装在一台机器上

这是实践中最容易踩的坑：

- **驱动冲突**：多款杀软的文件过滤驱动互相拦截，轻则蓝屏，重则系统起不来；
- **互相报毒**：Avast / Avira / 360 经常把彼此的核心文件判成 PUA；
- **Defender 降级**：安装任何第三方杀软后，Defender 会自动转入被动模式，实时防护关闭；
- **性能崩塌**：9 份实时监控同时挂钩文件系统，编译和扫描都会慢到不可用。

**推荐策略（按稳妥程度排序）：**

1. **常驻一款 + 绿色按需扫描器**（最推荐）
   常驻留一款（你们现在是火绒），其余用免安装扫描器：McAfee Stinger、卡巴 KVRT、
   ESET Online Scanner、Dr.Web CureIt。用完即删，互不干扰。

2. **分次装 / 扫 / 卸 + `merge`**
   一次只装一款，扫完卸载再换下一款，最后用 `python scan.py merge` 合并总报告。

3. **虚拟机/干净快照**
   每款杀软一个快照，扫完回滚。适合需要严格隔离的发布验证。

---

## 六、已知限制

- **Avira / Avast 的 CLI 参数随版本变化**：先 `--dry-run` 核对，再正式跑；
- **Malwarebytes 免费版**不接受指定路径，工具会直接报错而不是假装扫过；
- **超时不算无毒**：超时会标记为 `timeout` 并让总体结论变成「不通过（未完成全量验证）」；
- **不上传云端多引擎**：VirusTotal 之类会把文件传出去，公司安装包有合规风险，不内置；
- **不做自动清理/隔离**：Defender 走 `-DisableRemediation`，只检测不处置，避免误删安装包。

---

## 七、tools/ — 已下载的便携扫描器

2026-10-29 从各厂商官方源下载并逐个校验 Authenticode 数字签名（安全工具本身必须是正品，否则没有意义）。

| 引擎 | 文件 | 大小 | 签名 | 定向扫描 | 状态 |
|---|---|---|---|---|---|
| Kaspersky KVRT | `kvrt/KVRT.exe` | 116 MB | Kaspersky ✅ | ⚠️ 待实测 | 已下载 |
| Microsoft Safety Scanner | `msert/msert.exe` | 218 MB | Microsoft ✅ | ❌ 仅 `/F` 全盘 | 已下载 |
| Trellix Stinger | `stinger/stinger64.exe` | 48 MB | Musarubra(Trellix) ✅ | ⚠️ 待实测 | **已接入** |
| Dr.Web CureIt | — | ~200 MB | — | ⚠️ 待实测 | ❌ 下载过慢已终止 |
| ClamAV | — | 215 MB | — | ✅ `clamscan` | ❌ GitHub 限速已终止 |

> `tools/emsisoft/` 目录仍保留在磁盘上（GUI 版可手动使用），但**已从引擎注册表移除**，`detect` 不会再识别它。

### 实测结论（重要）

**1. `msert.exe` 不能指定路径**

只有 `/Q`（静默）、`/F`（全盘）、`/N`（只检测）等开关，**没有指定目录的参数**。它只能做全盘体检，无法对单个安装包定向扫描，因此不适合发布前验证场景。微软官方并未发布完整的命令行参考，`/N` 等开关是从 MRT.exe 借来的，行为需自行验证。

**2. Stinger 需要管理员权限**

非提权运行会抛 `WinError 740`（请求的操作需要提升），工具会判为 `error` 并让总结论转 `incomplete`，不会误报无毒。要用 Stinger 扫描，需以管理员身份启动终端。

**3. Git Bash 下调用会踩参数转换的坑**

Git Bash（MSYS2）会把 `/f=C:\path` 这类开关当成路径做转换，导致厂商 CLI 报"参数不正确"（退出码 4）。**用 PowerShell 或 Python subprocess 调用没问题**——`avscan` 走的是后者，所以不受影响。后续接入新引擎时，手工验证请用 PowerShell，别用 Git Bash。

---

## 八、目录结构

```
scan/
├── scan.py                  # 入口
├── avscan/
│   ├── paths.py             # 全盘程序目录枚举 + 注册表反查
│   ├── engines.py           # 9 款引擎注册表（探测/命令/解析）
│   ├── targets.py           # 扫描目标解析（目录/文件/高危过滤）
│   ├── runner.py            # 串行执行器（超时、进程树清理、原始输出落盘）
│   ├── report.py            # 报告生成（MD/CSV/JSON + 核对单 + 人工合并）
│   ├── merge.py             # 多次运行合并
│   ├── selftest.py          # 解析器自检样本
│   └── cli.py               # 命令入口
├── assets/                  # 品牌资源
│   ├── avscan.ico           # exe 与窗口图标（16–256 多尺寸）
│   ├── logo_1024.png        # 主图
│   ├── logo_24.png          # 侧边栏 / 标题栏（16–24px 简化版）
│   └── logo_light_512.png   # 浅色版
├── tools/                   # 便携扫描器（免安装，detect 自动识别）
│   ├── emsisoft/            # 保留未接入（GUI 版可手动使用）
│   ├── kvrt/KVRT.exe
│   ├── msert/msert.exe
│   └── stinger/stinger64.exe
├── packages/                # 安装包归档（559MB，不入 git）
│   ├── manifest.json        # 清单：版本/类型/静默参数（入库）
│   ├── huorong/ kaspersky/ malwarebytes/ 360/ avast/ avira/ qqpcmgr/ stinger/
│   └── junk/                # 非杀软包（360压缩）
└── runs/                    # 运行结果
```

---

## License

[MIT](LICENSE) © 2026 huangli007

本工具自身代码为 MIT。**随附的第三方杀软安装包与便携扫描器不在此协议范围内**，
其版权与许可归各自厂商所有，本仓库不收录这些二进制（需自行获取并放入 `packages/`、`tools/`）。

工具全程只读检测，不删除、不隔离、不修改任何被扫描文件。

