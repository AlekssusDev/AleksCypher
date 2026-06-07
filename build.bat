@echo off
chcp 65001 >nul
title Build AleksCypher
rustc --version >nul 2>&1
if errorlevel 1 (
    echo Rust не найден. Установите с https://rustup.rs
    pause
    exit /b 1
)
cargo build --release
echo.
if exist target\release\aleks_cypher.exe (
    echo Готово! Исполняемый файл: target\release\aleks_cypher.exe
) else (
    echo Ошибка сборки.
)
pause