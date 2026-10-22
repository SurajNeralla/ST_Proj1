@echo off
title PhishGuard AI - Automated Test Suite
cls
echo ========================================================
echo  Running PhishGuard AI Automated Detection Test Suite
echo ========================================================
echo.
node "%~dp0test_detector.js"
echo.
pause
