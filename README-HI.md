# AVENGER License Server — Hindi Setup

यह APACHI PRO से अलग नया AVENGER License Server है। इसमें अलग PostgreSQL database रखें; APACHI PRO का Render service या database edit न करें।

## सुविधाएँ
- Master Admin → Super Seller → Admin → Seller hierarchy
- अलग Admin login और responsive dashboard
- 30 दिन की license validity (generation से)
- एक license पर एक device binding
- License verify / activate / deactivate / renew / revoke / device reset
- Password bcrypt hash और license key का SHA-256 hash database में
- Activity logs
- Wallet/commission शामिल नहीं

## Local setup (Windows / VS Code)
1. ZIP extract करें और इसी `AVENGER_LICENSE_SERVER` folder को VS Code में खोलें।
2. Node.js 20 या नया install हो।
3. `.env.example` की copy बनाकर `.env` नाम दें।
4. PostgreSQL database `avenger_license` बनाएँ और `.env` में `DATABASE_URL` भरें।
5. `JWT_SECRET` में कम-से-कम 32 characters और `BOOTSTRAP_SECRET` में कम-से-कम 24 characters का random secret रखें।
6. Terminal में:
   ```bash
   npm install
   npm start
   ```
7. `http://localhost:10000/health` पर `{"ok":true}` आना चाहिए।

## Render पर deploy
1. GitHub में नया repository `avenger-license-server` बनाएँ और इस folder की सभी files push करें।
2. Render में New → PostgreSQL चुनें। Database का नाम `avenger-license-db` रखें।
3. Render में New → Web Service से GitHub repository connect करें।
4. Runtime Node, Build Command `npm install`, Start Command `npm start` रखें।
5. Web Service Environment में:
   - `DATABASE_URL`: AVENGER PostgreSQL का Internal Database URL
   - `NODE_ENV`: `production`
   - `JWT_SECRET`: लंबा random secret (कम-से-कम 32 characters)
   - `BOOTSTRAP_SECRET`: अलग random secret (कम-से-कम 24 characters)
   - `LICENSE_DAYS`: `30`
   - `DEVICE_LIMIT`: `1`
6. Deploy के बाद `https://YOUR-SERVICE.onrender.com/health` खोलें।

## पहला Master Admin बनाना
Deploy होने के बाद PowerShell में अपने Render URL और BOOTSTRAP_SECRET से यह चलाएँ (अपना मजबूत password रखें):

```powershell
$body = @{ username = "masteradmin"; displayName = "AVENGER Master Admin"; password = "ChangeThis-To-A-Long-Unique-Password" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "https://YOUR-SERVICE.onrender.com/api/bootstrap-master" -Headers @{ "x-bootstrap-secret" = "YOUR_BOOTSTRAP_SECRET" } -ContentType "application/json" -Body $body
```

सफलता के बाद Render Environment से `BOOTSTRAP_SECRET` हटा दें और service redeploy/restart करें। Admin Panel खोलने के लिए service का base URL खोलें और Master credentials से login करें।

## AVENGER desktop app connection — IMPORTANT
Backend provides:
- `POST /license/activate`
- `POST /license/verify`

The routes accept JSON with `licenseKey` (or `key`) and a device identifier (`deviceId`, `machineId`, `machine`, or `Machine`). They return JSON including `ok`, and status/reason fields. A license is bound to the first device that activates it.

**The desktop app is not automatically connected by deploying this server.** The AVENGER Electron app's `license-gate.js` must use this exact server base URL and send a compatible key + device ID request. Before production use, test with a newly generated key and inspect the app's `license-gate.js` request/response contract. Do not assume activation works until this test passes.

## Security
- Never commit `.env` or share secrets/passwords.
- Use the AVENGER database only; do not reuse APACHI PRO's database URL.
- Keep HTTPS enabled.
- Master bootstrap secret must be removed after first Master account creation.
- Test in a fresh database before selling or distributing licenses.
