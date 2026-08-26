# Phishing Email Detection System

A **Rule-Based** phishing email detection system built as a college mini-project.
This project analyzes emails using predefined keyword rules, regex pattern
matching and a points-based risk scoring system — **no AI, no Machine
Learning, no external APIs.**

---

## 1. Project Objective

To build a working system that can analyze an email's sender, subject and
body, and classify it as **SAFE**, **SUSPICIOUS**, or **PHISHING** based on
predefined security rules — the same kind of heuristics real-world email
filters used before ML-based filtering became common.

## 2. Problem Statement

Phishing emails trick users into revealing passwords, OTPs, and financial
details by imitating trusted organizations and creating a false sense of
urgency. Manually spotting every red flag is hard for an average user.

## 3. Proposed Solution

A web application where a user pastes in an email's sender, subject and
body. The backend runs the content through **10 predefined detection
rules**, each contributing points to a **risk score (0–100)**. The score
is mapped to a classification, saved to a local database, and shown to
the user with a clear explanation and list of detected indicators.

## 4. Features

- Analyze any email's sender / subject / body instantly
- 10 independent, transparent, explainable detection rules
- 0–100 point risk scoring system
- SAFE / SUSPICIOUS / PHISHING classification
- Full analysis history with view & delete
- Dashboard with live statistics (Total / Safe / Suspicious / Phishing)
- Local SQLite database — no external DB server required
- Clean, responsive, dependency-free frontend (HTML/CSS/JS only)
- Sample test emails built into the UI for quick demoing

## 5. Technologies Used

| Layer      | Technology                          |
|------------|--------------------------------------|
| Frontend   | HTML5, CSS3, Vanilla JavaScript      |
| Backend    | Java 17, Spring Boot 3.3             |
| Database   | SQLite (via `sqlite-jdbc`)           |
| ORM        | Spring Data JPA / Hibernate (with `hibernate-community-dialects` for SQLite) |
| Build Tool | Maven                                |

No AI/ML frameworks, no Python, no Node.js, no external AI APIs are used
anywhere in this project.

## 6. System Modules

1. **Home / Dashboard** — statistics overview
2. **Email Analysis** — input form + result display
3. **Rule-Based Detection Engine** — `RuleBasedDetectionService`
4. **SQLite Database** — persistent storage via JPA
5. **Analysis History** — table of past analyses with view/delete
6. **Dashboard Statistics API** — aggregated counts by classification

## 7. Architecture

```
Browser (HTML/CSS/JS)
        │  fetch() calls
        ▼
Spring Boot REST Controller  (EmailAnalysisController)
        │
        ▼
Service Layer
  ├─ RuleBasedDetectionService   (pure rule engine, no persistence)
  └─ EmailAnalysisService        (orchestration + persistence)
        │
        ▼
Repository Layer (Spring Data JPA)  →  SQLite database (phishing.db)
```

Clean separation: `controller` → `service` → `repository` → `entity`,
with `dto` classes used for request/response payloads so entities are
never exposed directly over the API.

## 8. Detection Rules

| # | Rule                          | Points | What it checks |
|---|--------------------------------|-------:|-----------------|
| 1 | Urgent language                | +10 | "urgent", "immediately", "act now", "account will be suspended", etc. |
| 2 | Password request                | +20 | "password", "login credentials", "confirm password", etc. |
| 3 | OTP request                     | +20 | "OTP", "verification code", "security code", etc. |
| 4 | Financial information request   | +20 | "bank account", "CVV", "PIN", "credit card", etc. |
| 5 | Suspicious link                 | +20 | `http://`, shortened-URL services, raw IP-address links |
| 6 | Prize / reward / scam language  | +15 | "you won", "lottery", "claim now", "lucky winner", etc. |
| 7 | Threatening language             | +10 | "account blocked", "legal action", "penalty", "warning" |
| 8 | Suspicious sender                | +15 | invalid format, lookalike domains (e.g. `paypa1`), brand-name mismatch |
| 9 | Excessive capital letters        |  +5 | >30% of letters are uppercase |
| 10| Excessive special characters     |  +5 | `!!!`, `???`, `$$$`, `@@`, or 6+ symbol characters |

All rule keyword lists and thresholds live in
`RuleBasedDetectionService.java` and can be freely edited/extended.

## 9. Risk Scoring

- Every matched rule adds its fixed point value to the total.
- The final score is clamped to the range **0–100**.
- Multiple rules can match the same email (they usually do, for real
  phishing emails), which is why serious phishing emails often score
  70–100.

## 10. Classification

| Score Range | Classification |
|-------------|-----------------|
| 0 – 30      | SAFE            |
| 31 – 60     | SUSPICIOUS      |
| 61 – 100    | PHISHING        |

## 11. Database Design

Table: `email_analysis` (auto-created by Hibernate on first run)

| Column               | Type      | Notes                          |
|-----------------------|-----------|--------------------------------|
| id                    | INTEGER   | Primary key, auto-increment    |
| sender_email          | TEXT      | Not null                       |
| subject               | TEXT      | Not null                       |
| email_body            | TEXT      | Not null (stored as CLOB/Lob)  |
| risk_score            | INTEGER   | 0–100                          |
| classification        | TEXT      | SAFE / SUSPICIOUS / PHISHING   |
| detected_indicators   | TEXT      | `|`-separated list of indicators |
| analyzed_at           | DATETIME  | Timestamp of analysis          |

The database file `phishing.db` is created automatically in the project
root the first time the application starts — no manual setup needed.

## 12. REST APIs

| Method | Endpoint                    | Description                    |
|--------|------------------------------|---------------------------------|
| POST   | `/api/emails/analyze`        | Analyze a new email             |
| GET    | `/api/emails`                 | Get full analysis history       |
| GET    | `/api/emails/{id}`            | Get one analysis by ID          |
| DELETE | `/api/emails/{id}`            | Delete an analysis record       |
| GET    | `/api/emails/statistics`      | Get dashboard statistics        |

### Example: Analyze Email

**Request**

```json
POST /api/emails/analyze
{
  "senderEmail": "support@example.com",
  "subject": "Urgent Account Verification",
  "emailBody": "Please verify your password immediately."
}
```

**Response**

```json
{
  "id": 1,
  "senderEmail": "support@example.com",
  "subject": "Urgent Account Verification",
  "riskScore": 30,
  "classification": "SAFE",
  "detectedIndicators": [
    "Urgent language detected",
    "Password request detected"
  ],
  "explanation": "...",
  "analyzedAt": "2026-08-23 10:15:00"
}
```

## 13. Project Structure

```
phishing-email-detection/
│
├── pom.xml
├── README.md
│
└── src/
    └── main/
        ├── java/com/example/phishing/
        │   ├── PhishingEmailDetectionApplication.java
        │   ├── controller/EmailAnalysisController.java
        │   ├── service/
        │   │   ├── EmailAnalysisService.java
        │   │   └── RuleBasedDetectionService.java
        │   ├── repository/EmailAnalysisRepository.java
        │   ├── entity/EmailAnalysis.java
        │   └── dto/
        │       ├── EmailRequest.java
        │       └── AnalysisResponse.java
        │
        └── resources/
            ├── application.properties
            └── static/
                ├── index.html
                ├── history.html
                ├── style.css
                └── script.js
```

## 14. Installation Requirements

- **Java 17** or higher (JDK)
- **Maven 3.6+** (or use the included wrapper if you generate one)
- A web browser
- VS Code (or any IDE) — optional but recommended

No database server, no Python, no Node.js required.

## 15. How to Run

1. Unzip the project and open the folder in **VS Code**.
2. Make sure Java 17+ is installed: `java -version`
3. Make sure Maven is installed: `mvn -version`
4. Open a terminal in the project root.
5. Run:

   ```bash
   mvn spring-boot:run
   ```

6. Wait for the console to show:

   ```
   Phishing Email Detection System started successfully!
   Open your browser at: http://localhost:8080
   ```

7. Open your browser and visit:

   ```
   http://localhost:8080
   ```

The database file `phishing.db` will be created automatically in the
project root on first run.

## 16. How to Test

Use the **"Try a sample"** buttons on the Analyze Email page to
instantly load one of the three built-in test emails (Safe /
Suspicious / Phishing), or paste in your own text.

### Sample: Safe Email
```
Sender:  newsletter@company.com
Subject: Monthly Newsletter
Body:    Hello, Here is your monthly newsletter. Thank you for subscribing.
```
Expected: **SAFE**

### Sample: Suspicious Email
```
Sender:  support@example.com
Subject: Important Security Notice
Body:    Please review your account information. You may need to verify your account.
```
Expected: **SUSPICIOUS**

### Sample: Phishing Email
```
Sender:  security@paypa1-alert.com
Subject: URGENT! Your Account Will Be Suspended
Body:    Your account will be blocked immediately. Click the link below and
         verify your password, OTP and credit card information.
```
Expected: **PHISHING**

## 17. Security Notes

- All input is validated both on the frontend and backend.
- Database queries use Spring Data JPA (parameterized queries) — no raw
  SQL string concatenation, so no SQL injection risk.
- Email body content is rendered as plain text (`textContent`), never
  injected as raw HTML — no script execution from analyzed content.
- No emails are ever sent, fetched, or opened by the system. It only
  analyzes text the user pastes in.
- No passwords or credentials are ever stored — only the analysis
  metadata and the pasted email text for record-keeping/history.

## 18. Limitations

- Rule-based systems can be evaded by attackers who avoid the exact
  keyword list, or produce false positives on legitimate emails that
  happen to mention words like "password" or "urgent".
- Does not follow or scan actual links — only checks the visible URL
  text for suspicious patterns.
- English-language keyword matching only.

## 19. Future Enhancements

- Allow uploading raw `.eml` files for automatic parsing.
- Add a configurable rules panel so users can tune keyword lists/points
  from the UI without editing code.
- Add authentication so each user has their own private history.
- Add CSV/PDF export of the analysis history.
- Optionally add a real link-reachability/safe-browsing check (still
  rule-based, not AI) as an additional module.

---

**This project uses Rule-Based Phishing Email Analysis only.**
It does **not** use Artificial Intelligence, Machine Learning, Deep
Learning, or any external AI API.
