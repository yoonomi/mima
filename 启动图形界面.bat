@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo 正在启动 Secure AES 加密系统图形界面...
echo.
echo 使用: F:\ana\python.exe
"F:\ana\python.exe" gui\app.py
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo 启动失败！请确保已安装 Python 和依赖。
    echo 运行: pip install -r requirements.txt
    pause
)
