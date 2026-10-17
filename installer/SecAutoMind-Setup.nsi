; SecAutoMind 安装器脚本（NSIS MUI2）
; 产品级安装体验：选择目录 → 安装 → 桌面/开始菜单快捷方式 → 安装后自动启动
; 编译: makensis.exe SecAutoMind-Setup.nsi

!include "MUI2.nsh"
!include "FileFunc.nsh"

; ── 元信息 ──
; ⚠️ APP_VERSION 默认值只是兜底，**真值源是 config.share.yaml 的 version**。
;    构建请走 installer/build_installer.py（它读 config.share.yaml 后以 /DAPP_VERSION= 传入）。
;    历史坑（2026-10-18 实测）：本文件写死 1.7.25，而实际产出的安装包叫
;    SecAutoMind-Setup-1.7.28-x64.exe —— 版本号靠人肉覆盖，文件自身与产物对不上。
;    故改为 !ifndef 守卫：命令行给了就用命令行的，没给才落到下面的兜底值。
!ifndef APP_VERSION
  !define APP_VERSION "1.7.28"
!endif
!define APP_NAME "SecAutoMind"
!define APP_PUBLISHER "闽江大学 · 网络空间安全学院"
!define APP_EXE "secautomind-ai.exe"
!define APP_URL "https://truefurina.github.io/SecAutoMind/"
!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}"

Name "${APP_NAME} ${APP_VERSION}"
OutFile "SecAutoMind-Setup-${APP_VERSION}-x64.exe"
InstallDir "$PROGRAMFILES64\SecAutoMind"
InstallDirRegKey HKLM "${UNINST_KEY}" "InstallLocation"
RequestExecutionLevel admin
Unicode true
SetCompressor /SOLID lzma

; ── 界面语言 ──
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "LICENSE.txt"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "SimpChinese"
!insertmacro MUI_LANGUAGE "English"

; ── 安装段 ──
Section "Main" SEC_MAIN
  SetOutPath "$INSTDIR"

  ; 主程序（单文件，双击即用、内置前端资源与默认配置）
  ; 注：原注释写死「158MB」——那是 09-05 构建的体积，现已 ~86MB（-w -s 裁剪 + 纯 Go sqlite）。
  ;     体积随代码变，注释不写具体数字，避免又一次「注释比产物旧」。
  File "secautomind-ai.exe"

  ; 许可证与说明
  File "README-INSTALL.txt"

  ; 写卸载信息
  WriteUninstaller "$INSTDIR\uninstall.exe"

  ; 开始菜单快捷方式
  CreateDirectory "$SMPROGRAMS\${APP_NAME}"
  CreateShortcut "$SMPROGRAMS\${APP_NAME}\${APP_NAME}.lnk" "$INSTDIR\${APP_EXE}" "" "$INSTDIR\${APP_EXE}"
  CreateShortcut "$SMPROGRAMS\${APP_NAME}\卸载 ${APP_NAME}.lnk" "$INSTDIR\uninstall.exe"
  CreateShortcut "$SMPROGRAMS\${APP_NAME}\官网.lnk" "${APP_URL}"

  ; 桌面快捷方式
  CreateShortcut "$DESKTOP\${APP_NAME}.lnk" "$INSTDIR\${APP_EXE}" "" "$INSTDIR\${APP_EXE}"

  ; 注册卸载（控制面板可见）
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayName" "${APP_NAME} ${APP_VERSION}"
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayVersion" "${APP_VERSION}"
  WriteRegStr HKLM "${UNINST_KEY}" "Publisher" "${APP_PUBLISHER}"
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayIcon" "$INSTDIR\${APP_EXE}"
  WriteRegStr HKLM "${UNINST_KEY}" "UninstallString" "$INSTDIR\uninstall.exe"
  WriteRegStr HKLM "${UNINST_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINST_KEY}" "URLInfoAbout" "${APP_URL}"
  WriteRegDWORD HKLM "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINST_KEY}" "NoRepair" 1
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  IntFmt $0 "0x%08X" $0
  WriteRegDWORD HKLM "${UNINST_KEY}" "EstimatedSize" "$0"

  ; 注册端口（Windows 防火墙放行 8080，避免首次运行弹防火墙）
  ; nsExec 需要插件，防火墙放行可选——这里用默认：不修改防火墙策略，
  ; 程序绑定 127.0.0.1 仅本机访问，无需放行。

  ; 安装完成后自动启动（勾选"运行"）
  ; （由 Finish 页 Readme/运行 回调处理）
SectionEnd

; ── 完成页：自动启动 ──
Function .onInstSuccess
  ; 静默安装时不弹窗
  ${IfNot} ${Silent}
    ExecShell "open" "$INSTDIR\${APP_EXE}"
  ${EndIf}
FunctionEnd

; ── 卸载段 ──
Section "Uninstall"
  ; 停掉正在运行的程序
  nsExec::ExecToLog 'taskkill /F /IM "${APP_EXE}" /T'
  Sleep 500

  ; 删快捷方式
  Delete "$DESKTOP\${APP_NAME}.lnk"
  Delete "$SMPROGRAMS\${APP_NAME}\${APP_NAME}.lnk"
  Delete "$SMPROGRAMS\${APP_NAME}\卸载 ${APP_NAME}.lnk"
  Delete "$SMPROGRAMS\${APP_NAME}\官网.lnk"
  RMDir "$SMPROGRAMS\${APP_NAME}"

  ; 删文件（保留用户数据目录 data/——产品级卸载不删用户数据）
  Delete "$INSTDIR\uninstall.exe"
  Delete "$INSTDIR\${APP_EXE}"
  Delete "$INSTDIR\README-INSTALL.txt"
  RMDir "$INSTDIR"

  ; 删注册表
  DeleteRegKey HKLM "${UNINST_KEY}"
SectionEnd
