#!/usr/bin/env bash
# ============================
# SMTP environment variables
# Customize the values below
# ============================
export SMTP_HOST="smtp.example.com"
export SMTP_PORT="587"
export SMTP_USER="username"
export SMTP_PASSWORD="change-me"
export SMTP_STARTTLS="true"
export TWILIGHT_DIGITAL_API_BASE_URL="http://localhost:8080"
export TWILIGHT_DIGITAL_LOG_LEVEL="INFO"
export MONGODB_URI="mongodb://localhost:27017"
export MONGODB_DB="TwilightDigital"

echo
echo "SMTP environment variables exported for this shell session:"
echo "  SMTP_HOST=$SMTP_HOST"
echo "  SMTP_PORT=$SMTP_PORT"
echo "  SMTP_USER=$SMTP_USER"
echo "  SMTP_PASSWORD=********"
echo "  SMTP_STARTTLS=$SMTP_STARTTLS"
echo "  TWILIGHT_DIGITAL_API_BASE_URL=$TWILIGHT_DIGITAL_API_BASE_URL"
echo "  TWILIGHT_DIGITAL_LOG_LEVEL=$TWILIGHT_DIGITAL_LOG_LEVEL"
echo "  MONGODB_URI=$MONGODB_URI"
echo "  MONGODB_DB=$MONGODB_DB"
echo
echo "Tip: source this file to keep variables in your current shell:"
echo "  source ./set_env.sh"
