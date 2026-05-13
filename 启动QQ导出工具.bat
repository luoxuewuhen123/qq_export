@echo off
chcp 65001 >nul 2>&1
title QQ聊天记录导出工具
echo ========================================
echo   🐧 QQ聊天记录导出工具 v1.0
echo ========================================
echo.
echo 正在启动...
echo.

cd /d "%~dp0"

python qq_export_gui.py

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ❌ 启动失败！请检查：
    echo   1. Python 是否已安装
    echo   2. PyQt5 是否已安装 (pip install PyQt5)
    echo   3. sqlcipher3 是否已安装 (pip install sqlcipher3)
    echo.
)

pause
