@echo off
echo ===================================================
echo   Cloudflare Worker Secret Env-Uploader Script
echo ===================================================
echo.

if not exist .env (
    echo [ERROR] .env file not found!
    echo Please copy .env.example to .env and fill in your keys.
    exit /b 1
)

echo [INFO] Found .env file.
echo.

:: 1. Sync GITHUB_CLIENT_ID into wrangler.toml if it is defined in .env
powershell -Command "$envFile = Get-Content .env; foreach ($line in $envFile) { if ($line -match '^GITHUB_CLIENT_ID=(.*)$') { $cid = $Matches[1].Trim(); if ($cid -and $cid -ne 'PLACEHOLDER_GITHUB_CLIENT_ID') { write-host '[INFO] Syncing GITHUB_CLIENT_ID to wrangler.toml...'; (gc wrangler.toml) -replace 'PLACEHOLDER_GITHUB_CLIENT_ID', $cid | Out-File -encoding UTF8 wrangler.toml; break; } } }"

:: 2. Upload secrets automatically from .env
echo [INFO] Uploading secrets to Cloudflare...
powershell -Command "$envFile = Get-Content .env; foreach ($line in $envFile) { if ($line -match '^(GITHUB_CLIENT_SECRET|RESEND_API_KEY|TURNSTILE_SECRET_KEY|CONTACT_TO_EMAIL|ADMIN_EMAILS|MODERATION_SECRET)=(.*)$') { $name = $Matches[1].Trim(); $val = $Matches[2].Trim(); if ($val) { write-host \"[+] Uploading secret: $name ...\"; echo $val | npx wrangler secret put $name } } }"

echo.
echo [INFO] Secrets configuration complete. Deploying worker...
npx wrangler deploy

echo.
echo ===================================================
echo Deploy finished! Please verify your endpoints.
echo ===================================================
pause
