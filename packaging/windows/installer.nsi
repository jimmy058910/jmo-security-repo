
; JMo Security Installer v0.9.0
; NSIS Installer Script
; https://nsis.sourceforge.io/

!define APP_NAME "JMo Security"
!define APP_VERSION "0.9.0"
!define APP_PUBLISHER "JMo Tools"
!define APP_URL "https://jmotools.com"
!define APP_SUPPORT_URL "https://github.com/jimmy058910/jmo-security-repo/issues"
!define APP_README "https://docs.jmotools.com"

; Installer name and output file
Name "${APP_NAME} ${APP_VERSION}"
OutFile "jmo-security-${APP_VERSION}-win64.exe"
InstallDir "$LOCALAPPDATA\JMo Security"
InstallDirRegKey HKCU "Software\JMo Security" "InstallDir"

; Request user permissions
RequestExecutionLevel user

; Modern UI
!include "MUI2.nsh"

; MUI Settings
!define MUI_ABORTWARNING
!define MUI_ICON "${NSISDIR}\Contrib\Graphics\Icons\modern-install.ico"
!define MUI_UNICON "${NSISDIR}\Contrib\Graphics\Icons\modern-uninstall.ico"

; Welcome page
!insertmacro MUI_PAGE_WELCOME

; License page
!define MUI_LICENSEPAGE_TEXT_TOP "JMo Security is dual-licensed under MIT OR Apache-2.0"
!insertmacro MUI_PAGE_LICENSE "..\..\LICENSE"

; Directory page
!insertmacro MUI_PAGE_DIRECTORY

; Installation page
!insertmacro MUI_PAGE_INSTFILES

; Finish page
!define MUI_FINISHPAGE_RUN "$INSTDIR\jmo.exe"
!define MUI_FINISHPAGE_RUN_PARAMETERS "--help"
!define MUI_FINISHPAGE_RUN_TEXT "View JMo Security help"
!define MUI_FINISHPAGE_SHOWREADME "${APP_README}"
!define MUI_FINISHPAGE_SHOWREADME_TEXT "Open online documentation"
!insertmacro MUI_PAGE_FINISH

; Uninstaller pages
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

; Language
!insertmacro MUI_LANGUAGE "English"

; Installer sections
Section "Install" SecInstall
    SetOutPath "$INSTDIR"

    ; Copy executable
    File "..\..\dist\jmo.exe"

    ; Copy documentation
    File "..\..\README.md"
    File "..\..\LICENSE"
    File "..\..\LICENSE-MIT"
    File "..\..\LICENSE-APACHE"

    ; Create Start Menu shortcuts
    CreateDirectory "$SMPROGRAMS\${APP_NAME}"
    CreateShortcut "$SMPROGRAMS\${APP_NAME}\JMo Security CLI.lnk" "$INSTDIR\jmo.exe" "--help" "$INSTDIR\jmo.exe" 0
    CreateShortcut "$SMPROGRAMS\${APP_NAME}\JMo Security Wizard.lnk" "$INSTDIR\jmo.exe" "wizard" "$INSTDIR\jmo.exe" 0
    CreateShortcut "$SMPROGRAMS\${APP_NAME}\Documentation.lnk" "${APP_README}"
    CreateShortcut "$SMPROGRAMS\${APP_NAME}\Uninstall.lnk" "$INSTDIR\Uninstall.exe"

    ; Write uninstaller
    WriteUninstaller "$INSTDIR\Uninstall.exe"

    ; Write registry keys for Add/Remove Programs
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" "DisplayName" "${APP_NAME}"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" "DisplayVersion" "${APP_VERSION}"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" "Publisher" "${APP_PUBLISHER}"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" "URLInfoAbout" "${APP_URL}"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" "HelpLink" "${APP_SUPPORT_URL}"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" "UninstallString" "$INSTDIR\Uninstall.exe"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" "InstallLocation" "$INSTDIR"
    WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" "NoModify" 1
    WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" "NoRepair" 1

    ; Store installation directory
    WriteRegStr HKCU "Software\JMo Security" "InstallDir" "$INSTDIR"

    ; Add to PATH (user level) - Native NSIS approach
    ReadRegStr $0 HKCU "Environment" "Path"
    StrCmp $0 "" 0 +2
        StrCpy $0 "$INSTDIR"
    StrCpy $1 "$0"
    ; Check if already in PATH
    Push "$INSTDIR"
    Push "$1"
    Call StrStr
    Pop $2
    StrCmp $2 "" 0 +2
        WriteRegExpandStr HKCU "Environment" "Path" "$INSTDIR;$0"

    ; Broadcast WM_SETTINGCHANGE to notify applications of PATH change
    SendMessage ${HWND_BROADCAST} ${WM_SETTINGCHANGE} 0 "STR:Environment" /TIMEOUT=5000

    ; Success message with Windows compatibility notice
    MessageBox MB_OK "JMo Security ${APP_VERSION} installed successfully!$\r$\n$\r$\n7/12 security tools work natively on Windows$\r$\n5/12 tools require WSL2 or Docker$\r$\n$\r$\nRecommended Windows Setup:$\r$\n  1. Install WSL2 + Docker Desktop (for all 12 tools)$\r$\n  2. Run: jmo wizard --docker$\r$\n$\r$\nNative Windows (limited to 7 tools):$\r$\n  - Run: jmo wizard$\r$\n  - Use --profile fast or --profile balanced$\r$\n  - Tools: TruffleHog, Trivy, Syft, Checkov, Hadolint, Nuclei, Bandit$\r$\n$\r$\nDocumentation: ${APP_README}"

SectionEnd

; Uninstaller section
Section "Uninstall"
    ; Remove files
    Delete "$INSTDIR\jmo.exe"
    Delete "$INSTDIR\README.md"
    Delete "$INSTDIR\LICENSE"
    Delete "$INSTDIR\LICENSE-MIT"
    Delete "$INSTDIR\LICENSE-APACHE"
    Delete "$INSTDIR\Uninstall.exe"

    ; Remove Start Menu shortcuts
    Delete "$SMPROGRAMS\${APP_NAME}\JMo Security CLI.lnk"
    Delete "$SMPROGRAMS\${APP_NAME}\JMo Security Wizard.lnk"
    Delete "$SMPROGRAMS\${APP_NAME}\Documentation.lnk"
    Delete "$SMPROGRAMS\${APP_NAME}\Uninstall.lnk"
    RMDir "$SMPROGRAMS\${APP_NAME}"

    ; Remove installation directory
    RMDir "$INSTDIR"

    ; Remove from PATH (user level) - Native NSIS approach
    ReadRegStr $0 HKCU "Environment" "Path"
    Push "$INSTDIR"
    Push "$0"
    Call un.RemoveFromPath
    Pop $1
    WriteRegExpandStr HKCU "Environment" "Path" "$1"

    ; Broadcast WM_SETTINGCHANGE
    SendMessage ${HWND_BROADCAST} ${WM_SETTINGCHANGE} 0 "STR:Environment" /TIMEOUT=5000

    ; Remove registry keys
    DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}"
    DeleteRegKey HKCU "Software\JMo Security"

    MessageBox MB_OK "JMo Security has been uninstalled."

SectionEnd

; Helper function: Check if string contains substring
Function StrStr
    Exch $R1 ; haystack
    Exch
    Exch $R2 ; needle
    Push $R3
    Push $R4
    Push $R5
    StrLen $R3 $R2
    StrCpy $R4 0
    loop:
        StrCpy $R5 $R1 $R3 $R4
        StrCmp $R5 $R2 done
        StrCmp $R5 "" done
        IntOp $R4 $R4 + 1
        Goto loop
    done:
        StrCpy $R1 $R5
        Pop $R5
        Pop $R4
        Pop $R3
        Pop $R2
        Exch $R1
FunctionEnd

; Helper function: Remove directory from PATH
Function un.RemoveFromPath
    Exch $0 ; path to remove
    Exch
    Exch $1 ; current PATH
    Push $2
    Push $3
    Push $4
    Push $5
    StrCpy $2 $1 1 -1
    StrCmp $2 ";" +2
        StrCpy $1 "$1;" ; Ensure trailing semicolon
    Push $1
    Push "$0;"
    Call un.StrStr
    Pop $2
    StrCmp $2 "" unRemoveFromPath_done
        StrLen $3 "$0;"
        StrLen $4 $2
        StrCpy $5 $1 -$4
        StrCpy $5 "$5$2" "" $3
        StrCpy $1 $5
    unRemoveFromPath_done:
        StrCpy $0 $1
        StrCpy $2 $0 1 -1
        StrCmp $2 ";" 0 +2
            StrCpy $0 $0 -1 ; Remove trailing semicolon
        Pop $5
        Pop $4
        Pop $3
        Pop $2
        Pop $1
        Exch $0
FunctionEnd

; Helper function for uninstaller: StrStr
Function un.StrStr
    Exch $R1
    Exch
    Exch $R2
    Push $R3
    Push $R4
    Push $R5
    StrLen $R3 $R2
    StrCpy $R4 0
    loop_un:
        StrCpy $R5 $R1 $R3 $R4
        StrCmp $R5 $R2 done_un
        StrCmp $R5 "" done_un
        IntOp $R4 $R4 + 1
        Goto loop_un
    done_un:
        StrCpy $R1 $R5
        Pop $R5
        Pop $R4
        Pop $R3
        Pop $R2
        Exch $R1
FunctionEnd
