@echo off
setlocal
python "%~dp0burpzip.py" %*
exit /b %errorlevel%
