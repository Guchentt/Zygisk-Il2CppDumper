# GitHub Actions 构建指南

## 使用 GitHub Actions 自动构建 Zygisk-Il2CppDumper 模块

### 方法一：Fork 项目后使用 GitHub Actions（推荐）

#### 步骤 1: Fork 项目
1. 访问项目仓库页面
2. 点击右上角的 **Fork** 按钮
3. 选择要 Fork 到的账户

#### 步骤 2: 启用 GitHub Actions
1. 进入你 Fork 的仓库
2. 点击 **Actions** 标签页
3. 如果提示需要启用 Actions，点击 **I understand my workflows, go ahead and enable them**

#### 步骤 3: 运行构建
1. 在 **Actions** 标签页左侧，选择 **Build** 工作流
2. 点击右侧的 **Run workflow** 按钮
3. 在弹出的表单中：
   - **Use workflow from**: 选择 `main` 分支
   - **Package name of the game**: 输入目标游戏的包名（例如：`com.game.example`）
   - 点击绿色的 **Run workflow** 按钮

#### 步骤 4: 下载构建产物
1. 等待构建完成（通常需要 3-5 分钟）
2. 在构建详情页面，滚动到底部找到 **Artifacts** 区域
3. 点击 **zygisk-il2cppdumper** 下载
4. 下载的 ZIP 文件即为可安装的 Magisk 模块

---

### 方法二：手动输入包名（无需修改源码）

GitHub Actions 已配置为通过工作流输入包名，无需修改源码即可构建。

**优势：**
- 不需要手动编辑 `game.h` 文件
- 每次可以为不同包名构建
- 保持仓库原始状态

---

### 方法三：克隆后本地构建

如果你不想使用 GitHub Actions，也可以在本地构建。

#### Windows 环境

```powershell
# 1. 安装依赖
# - 安装 Java JDK 11 或更高版本
# - 安装 Android Studio 或 Android SDK

# 2. 配置环境变量
# 设置 ANDROID_HOME 环境变量指向 Android SDK 路径
# 例如: C:\Users\你的用户名\AppData\Local\Android\Sdk

# 3. 修改游戏包名
# 编辑 module/src/main/cpp/game.h 文件
# 将 com.game.packagename 替换为你的游戏包名

# 4. 构建
.\gradlew.bat :module:assembleRelease

# 5. 构建产物位置
# out/magisk_module_release/zygisk-il2cppdumper-v1.2.0-release.zip
```

#### Linux/macOS 环境

```bash
# 1. 安装依赖
# - 安装 OpenJDK 11 或更高版本
# - 安装 Android SDK 命令行工具

# 2. 配置环境变量
export ANDROID_HOME=/path/to/android/sdk
export PATH=$PATH:$ANDROID_HOME/cmdline-tools/latest/bin

# 3. 修改游戏包名
# 编辑 module/src/main/cpp/game.h 文件
# 将 com.game.packagename 替换为你的游戏包名

# 4. 构建
chmod +x gradlew
./gradlew :module:assembleRelease

# 5. 构建产物位置
# out/magisk_module_release/zygisk-il2cppdumper-v1.2.0-release.zip
```

---

### 使用 Android Studio 构建

1. 用 Android Studio 打开项目
2. 等待 Gradle 同步完成
3. 修改 `module/src/main/cpp/game.h` 中的包名
4. 在右侧 Gradle 面板中找到：
   ```
   Zygisk-Il2CppDumper
   ├── Tasks
   │   └── module
   │       └── build
   │           └── assembleRelease
   ```
5. 双击 `assembleRelease` 开始构建
6. 构建完成后，在 `out/magisk_module_release/` 目录找到生成的 ZIP 文件

---

### 构建产物说明

构建完成后会生成一个 Magisk 模块 ZIP 文件，包含：

```
zygisk-il2cppdumper-v1.2.0-release.zip
├── module.prop                    # 模块信息
├── common/                        # 公共脚本
└── zygisk/
    ├── arm64-v8a.so              # ARM64 架构
    ├── armeabi-v7a.so            # ARMv7 架构
    ├── x86.so                    # x86 架构
    └── x86_64.so                 # x86_64 架构
```

---

### 安装和使用

1. **安装模块**：
   ```bash
   # 使用 adb 推送到设备
   adb push zygisk-il2cppdumper-v1.2.0-release.zip /sdcard/
   
   # 或者直接在 Magisk 中安装
   # 打开 Magisk -> 模块 -> 从本地安装 -> 选择 ZIP 文件
   ```

2. **重启设备**：
   ```bash
   adb reboot
   ```

3. **启动游戏**：
   - 启动配置的目标游戏
   - 模块会自动导出文件

4. **导出文件位置**：
   ```
   /data/data/<游戏包名>/files/
   ├── dump.cs                   # C# 源码
   ├── global-metadata.dat       # 未加密的元数据文件
   └── script.json                # 脚本映射文件
   ```

5. **提取导出文件**：
   ```bash
   # 需要 root 权限
   adb shell
   su
   cd /data/data/<游戏包名>/files/
   tar -czf /sdcard/il2cpp_dump.tar.gz *.cs *.dat *.json
   exit
   exit
   adb pull /sdcard/il2cpp_dump.tar.gz .
   ```

---

### 故障排除

#### 1. 构建失败：SDK 未找到

```bash
# 设置 ANDROID_HOME 环境变量
export ANDROID_HOME=/path/to/android/sdk
```

#### 2. 权限错误（Linux/macOS）

```bash
# 给予 gradlew 执行权限
chmod +x gradlew
```

#### 3. 游戏启动后没有导出文件

- 检查 Logcat 日志：
  ```bash
  adb logcat | grep -i il2cppdumper
  ```

- 确认包名配置正确
- 确认 Magisk 模块已启用
- 确认游戏使用 Il2Cpp 引擎

#### 4. global-metadata.dat 导出失败

- 查看 Logcat 日志中的错误信息
- 确认游戏已完全启动（Il2Cpp 初始化需要时间）
- 某些加密保护可能需要额外处理

---

### 高级配置

#### 修改模块信息

编辑 `module.gradle` 文件：

```gradle
ext {
    moduleLibraryName = "il2cppdumper"
    magiskModuleId = "zygisk_il2cppdumper"
    moduleName = "Il2CppDumper"                    // 模块名称
    moduleAuthor = "Perfare"                       // 作者
    moduleDescription = "Il2CppDumper Zygisk version."  // 描述
    moduleVersion = "v1.2.0"                       // 版本
    moduleVersionCode = 1                          // 版本代码
}
```

#### 修改目标 SDK 版本

编辑 `build.gradle` 文件：

```gradle
ext {
    minSdkVersion = 23      // 最低支持的 Android 版本
    targetSdkVersion = 32   // 目标 Android 版本
}
```

---

### 相关资源

- [Magisk 官方文档](https://topjohnwu.github.io/Magisk/)
- [Zygisk 文档](https://github.com/topjohnwu/Zygisk)
- [Il2CppDumper 原版](https://github.com/Perfare/Il2CppDumper)
- [Unity Il2Cpp 文档](https://docs.unity3d.com/Manual/il2cpp-introduction.html)

---

### 许可证

本项目遵循原项目的许可证（MIT License）。
