# Publishing FEIA Scam Check on Google Play

The Android app lives in `mobile/`. It is a Capacitor 8 app (targetSdk 36, as Play
requires from 31 Aug 2026) that talks to this repo's Flask backend at `/api/v1/scan`.
GitHub Actions builds it, so you never need Android Studio.

```
Phone app (mobile/)  ──HTTPS──▶  Flask backend (PUBLIC_MODE=1, gunicorn)  ──▶  ForensicInvestigationAgent
      │                                   └── /privacy  (privacy policy URL for Play)
      └── offline rule-based check if the server can't be reached
```

## Timeline. Read this first.

| Step | Time |
|---|---|
| Deploy backend, create keystore, first CI build | ~1 hour |
| Play developer account (US$25, identity verification) | 1–3 days |
| Closed test with **12 testers opted in for 14 consecutive days** (personal accounts created after 13 Nov 2023) | **14 days minimum** |
| Production access review, then app review | ~1–7 days |

Once your closed test is live, the app **is on the Play Store** and installable from a Play link by
your testers. If your evaluation date is before the 14 days are up, demo it from the closed-testing
link and show the Play Console dashboard. Start the closed test as early as possible.

---

## 1. Deploy the backend (Render, free)

1. Push this repo to GitHub.
2. On https://render.com: **New → Blueprint**, pick the repo. `render.yaml` configures everything.
3. When asked, fill `DEVELOPER_NAME` and `CONTACT_EMAIL` (shown on the privacy page). `VT_API_KEY` is optional.
4. When it's live, open `https://<your-service>.onrender.com/api/v1/health`. It should return `{"status":"ok"}`.
5. Open `https://<your-service>.onrender.com/privacy`. This is your **Privacy policy URL** for Play.

The free tier sleeps after ~15 min idle, and the first scan then takes up to a minute. The app shows a
"waking up the server" message. **For the demo day, switch to the Starter plan** or open the health URL a minute before.

## 2. Create your upload key (once, keep it safe)

On any computer with Java (or in a GitHub Codespace):

```bash
keytool -genkeypair -v -keystore upload.jks -alias feia -keyalg RSA -keysize 2048 -validity 10000
base64 -w0 upload.jks > upload.jks.b64      # macOS: base64 -i upload.jks -o upload.jks.b64
```

**Never commit `upload.jks`.** Play App Signing holds the real signing key, so if you lose this upload
key, Google support can reset it. You still don't want to.

## 3. Add GitHub secrets

Repo → Settings → Secrets and variables → Actions → New repository secret:

| Secret | Value |
|---|---|
| `API_BASE_URL` | `https://<your-service>.onrender.com` (no trailing slash) |
| `KEYSTORE_BASE64` | contents of `upload.jks.b64` |
| `KEYSTORE_PASSWORD` | keystore password from step 2 |
| `KEY_ALIAS` | `feia` |
| `KEY_PASSWORD` | key password from step 2 |

## 4. Build

Actions tab → **Android build (Play Store)** → Run workflow. When it's green, the run page has two artifacts:

- `feia-debug-apk-vN`: install on your phone to test (allow "install unknown apps").
- `feia-release-aab-vN`: the file you upload to Play.

Every run gets a higher `versionCode` automatically, so re-uploads are never rejected for that.

**Test on a real phone before uploading:** open WhatsApp or Messages, long-press a message,
choose Share, then **Check for scam**. The app should open and check it.

## 5. Play Console

### Create the app
- App name: **FEIA Scam Check** · Default language: English (India) · App · Free.

### Store listing (Grow → Store presence → Main store listing)
- **Short description (≤80):** `Check if an SMS, WhatsApp message, link or email is a scam. Get clear next steps.`
- **Full description:**

  > Got a message saying your KYC has expired, your electricity will be cut tonight, or you've won a prize? Check it before you tap.
  >
  > FEIA Scam Check examines links, SMS and WhatsApp messages, and full emails for signs of phishing and fraud, and tells you plainly: Scam, Careful, or Looks safe.
  >
  > • Share any message straight into the app from WhatsApp, Messages, Gmail or your browser
  > • Paste a link or open an email file (.eml) to check sender spoofing, SPF/DKIM and hidden links
  > • See exactly why: fake bank or KYC links, risky web addresses, pressure tactics, OTP requests
  > • Clear next steps, including the 1930 cyber-fraud helpline and cybercrime.gov.in
  > • Works offline with a basic on-device check when you have no connection
  > • No ads, no tracking, no account. The app never reads your SMS inbox or contacts
  >
  > Built as a final-year cybersecurity project: the Forensic Evidence Intelligence Agent, which combines machine-learning classifiers with forensic checks and explains every finding.
  >
  > Results are automated and can be wrong. Not affiliated with any bank, payment app or government body.

- **App icon:** `mobile/store/icon-512.png`
- **Feature graphic:** `mobile/store/feature-graphic-1024x500.png`
- **Phone screenshots:** `mobile/store/screenshots/phone-*.png` (1080×1921, 9:16)
- Category: **Tools** · Contact email: yours · Privacy policy: your `/privacy` URL

### App content (Policy → App content). Answers for this app:
| Item | Answer |
|---|---|
| Privacy policy | `https://<your-service>.onrender.com/privacy` |
| Ads | No ads |
| App access | All functionality available without special access (no login) |
| Content rating | Questionnaire category "Utility, Productivity, Communication, or Other"; answer No to all content questions |
| Target audience | **18 and over** (keeps the app out of the Families policy) |
| News app | No |
| Government app | **No**. Don't imply affiliation with government or banks |
| Financial features | My app doesn't provide any financial features |
| Health | No |
| Data safety | See below |

### Data safety form
- Does your app collect or share user data? **Yes** (messages the user submits are sent to the server).
- Is all data encrypted in transit? **Yes** (HTTPS only; cleartext is disabled in the manifest).
- Can users request deletion? **Yes**: nothing is stored server-side, and history is deleted in-app. Use `/privacy#deletion` as the URL.
- Data types: **Messages → Other in-app messages**: Collected, **not shared**, **processed ephemerally** (tick it), **not optional**, purpose **App functionality**.
- If you set `VT_API_KEY`: **Web browsing → Other / URLs** are **shared** with VirusTotal for **Fraud prevention, security, and compliance**. If you don't set it, nothing is shared.
- No location, contacts, identifiers, device IDs, or analytics.

## 6. Closed test → production

1. Testing → **Closed testing** → create track → upload `app-release.aab` → release notes → Review → **Start rollout**.
2. Add **at least 12 testers** (classmates' Gmail addresses, or a Google Group). Send them the opt-in link. Each must opt in, install from Play, and stay opted in for **14 days**.
3. Ask testers to actually use it (share 2–3 messages each). Google checks engagement.
4. After 14 days: Dashboard → **Apply for production**. Answer honestly how testers used it and what you changed.
5. After approval: Production → create release → same or newer `.aab` → roll out.

## 7. What can get you rejected, and what's already handled

| Risk | Status |
|---|---|
| Target SDK below 36 | Targets 36 |
| "Minimum functionality" (just a website in a WebView) | Native share-sheet intake, offline engine, local history, bundled UI |
| Missing/unreachable privacy policy | Served by backend at `/privacy`. **Must be live when you submit** |
| Impersonation of banks / govt | Name and listing state no affiliation. Keep it that way |
| Server down during review | Use the Starter plan during review week, or the reviewer sees only the offline check |
| Personal data leaks | `PUBLIC_MODE=1` disables the shared investigations DB, history/sniffer/IMAP routes |

## Local development

```bash
# backend (local analyst mode, full dashboard)
python app.py                                  # http://localhost:5000
# backend tests
PUBLIC_MODE=1 python -m pytest test_mobile_api.py -q
# app
cd mobile && npm ci && npm test && npm run build && npx cap sync android
npx cap open android                           # only if you have Android Studio
python3 tools/make_icons.py                    # regenerate icons / store graphics
```
