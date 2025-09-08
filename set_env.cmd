@echo off
REM ============================
REM SMTP environment variables
REM Customize the values below
REM ============================
set SMTP_HOST="[SMTP_HOST]"
setx SMTP_HOST %SMTP_HOST%
set SMTP_PORT="587"
setx SMTP_PORT %SMTP_PORT%
set SMTP_USER="[SMTP_USER]"
setx SMTP_USER %SMTP_USER%
set SMTP_PASSWORD="[SMTP_PASSWORD]"
setx SMTP_PASSWORD %SMTP_PASSWORD%
set SMTP_STARTTLS="true"
setx SMTP_STARTTLS %SMTP_STARTTLS%
set TWILIGHT_DIGITAL_API_BASE_URL="http://localhost:8080"
setx TWILIGHT_DIGITAL_API_BASE_URL %TWILIGHT_DIGITAL_API_BASE_URL%
set TWILIGHT_DIGITAL_LOG_LEVEL="INFO"
setx TWILIGHT_DIGITAL_LOG_LEVEL %TWILIGHT_DIGITAL_LOG_LEVEL%
set MONGODB_URI="mongodb://localhost:27017"
setx MONGODB_URI %MONGODB_URI%
set MONGODB_DB="TwilightDigital"
setx MONGODB_DB %MONGODB_DB%

echo.
echo SMTP environment variables set for this Command Prompt session:
echo   SMTP_HOST=%SMTP_HOST%
echo   SMTP_PORT=%SMTP_PORT%
echo   SMTP_USER=%SMTP_USER%
echo   SMTP_PASSWORD=********
echo   SMTP_STARTTLS=%SMTP_STARTTLS%
echo   TWILIGHT_DIGITAL_API_BASE_URL=%TWILIGHT_DIGITAL_API_BASE_URL%
echo   TWILIGHT_DIGITAL_LOG_LEVEL=%TWILIGHT_DIGITAL_LOG_LEVEL%
echo   MONGODB_URI=%MONGODB_URI%
echo   MONGODB_DB=%MONGODB_DB%
echo.
echo Tip: Run this script from an open Command Prompt window (e.g., `call set_env.cmd`)
echo      so the variables remain available in this session.
