@echo off
echo ===================================================
echo   Cloudflare Worker Secret Configuration Script
echo ===================================================
echo.
set /p GITHUB_CLIENT_ID="Enter your GitHub OAuth Client ID: "
set /p GITHUB_CLIENT_SECRET="Enter your GitHub OAuth Client Secret: "
set /p RESEND_API_KEY="Enter your Resend API Key: "
set /p TURNSTILE_SECRET_KEY="Enter your Cloudflare Turnstile Secret Key: "
set /p CONTACT_TO_EMAIL="Enter your Moderator Inbox Email (e.g. tavricccc@gmail.com): "
set /p ADMIN_EMAILS="Enter Admin Emails (comma-separated, e.g. tavricccc@gmail.com): "
set /p MODERATION_SECRET="Enter a random long string for Moderation Signatures: "
echo.
echo Saving GITHUB_CLIENT_ID to wrangler.toml...
powershell -Command "(gc wrangler.toml) -replace 'PLACEHOLDER_GITHUB_CLIENT_ID', '%GITHUB_CLIENT_ID%' | Out-File -encoding UTF8 wrangler.toml"

echo.
echo Setting secrets in Cloudflare Worker...
echo %GITHUB_CLIENT_SECRET%| npx wrangler secret put GITHUB_CLIENT_SECRET
echo %RESEND_API_KEY%| npx wrangler secret put RESEND_API_KEY
echo %TURNSTILE_SECRET_KEY%| npx wrangler secret put TURNSTILE_SECRET_KEY
echo %CONTACT_TO_EMAIL%| npx wrangler secret put CONTACT_TO_EMAIL
echo %ADMIN_EMAILS%| npx wrangler secret put ADMIN_EMAILS
echo %MODERATION_SECRET%| npx wrangler secret put MODERATION_SECRET
echo.
echo All secrets configured! Deploying worker...
npx wrangler deploy
echo.
echo ===================================================
echo Done! Please run git diff to verify changes.
echo ===================================================
pause
