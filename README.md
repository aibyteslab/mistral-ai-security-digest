# Mistral AI Security Digest

Automated daily email digest combining AI industry news and security vulnerability monitoring across your infrastructure stack. Powered by **Mistral AI** for formatting, **Perplexity** for real-time search, **OSV.dev** for structured CVE data, and **CVEProject/cvelistV5** for official CVE tracking.

The monitored software list is fully customizable — add or remove any package, OS, or framework to match your own infrastructure.

---

## How It Works

The script orchestrates 5 data sources into a single HTML email, delivered daily via SMTP:

```
Perplexity sonar-pro  →  AI news + WordPress vulns + Infra vulns (web search)
OSV.dev REST API      →  Structured CVE data for specific packages
CVEProject/cvelistV5  →  Official CVE list from GitHub (updated hourly)
Mistral API           →  Formats + merges all raw data into clean HTML
SMTP                  →  Delivers the final email
```

### Pipeline Steps

| Step | Source | Purpose |
|------|--------|---------|
| 1 | **Perplexity sonar-pro** | Real-time web search for AI news, WordPress vulns, infrastructure vulns |
| 2 | **OSV.dev** | Batch API query for structured vulnerability data by ecosystem/package |
| 3 | **CVEProject/cvelistV5** | Fetches last 24h of CVEs from GitHub, filters by target keywords |
| 4 | **Mistral mistral-large-latest** | Formats all raw data into 4 HTML email sections |
| 5 | **SMTP** | Sends the branded HTML email |

### Email Sections

1. **AI Industry News** — Latest developments for tracked AI topics (48h window)
2. **WordPress Vulnerabilities** — Plugin, theme, and core vulns (Perplexity + cvelistV5)
3. **Infrastructure & Package Vulnerabilities** — OSV.dev + Perplexity merged, grouped by package
4. **Official CVE List** — Infrastructure-related CVEs from CVEProject/cvelistV5

---

## Monitored Targets

### AI Topics
- Anthropic Claude AI, Claude Code, Claude API updates
- Mistral AI, OpenAI GPT, Google Gemini AI
- AI Security

### Infrastructure Packages (OSV.dev)

| Package | Ecosystem |
|---------|-----------|
| Ubuntu 20.04 / 24.04 LTS | Ubuntu |
| AlmaLinux 9 | AlmaLinux |
| Docker | Go |
| n8n | npm |
| Nginx | Debian |
| PHP 8.1 | Ubuntu |
| MariaDB | Ubuntu |
| phpMyAdmin | Packagist |
| AWS SDK | npm |
| Azure SDK | npm |
| Google Cloud | PyPI |
| Windows 11 | Perplexity only |

### CVE Keywords (cvelistV5 matching)
`linux`, `ubuntu`, `almalinux`, `kernel`, `docker`, `container`, `n8n`, `nginx`, `php`, `mariadb`, `mysql`, `phpmyadmin`, `aws`, `azure`, `windows`, `wordpress`

WordPress-matched CVEs are routed to the WordPress section; all others go to the CVE List section.

---

## Setup

### 1. Clone and install

```bash
cd /opt/daily-news  # or wherever you prefer
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure environment

Create a `.env` file in the project directory:

```bash
cp .env.example .env
# Edit .env with your credentials
```

| Variable | Required | Description |
|----------|----------|-------------|
| `MISTRAL_API_KEY` | Yes | Mistral API key from [console.mistral.ai](https://console.mistral.ai) |
| `PERPLEXITY_API_KEY` | Yes | Perplexity API key from [perplexity.ai](https://www.perplexity.ai) |
| `SMTP_HOST` | Yes | SMTP server hostname |
| `SMTP_PORT` | Yes | `587` for STARTTLS, `465` for SSL |
| `SMTP_USER` | Yes | SMTP login email |
| `SMTP_PASS` | Yes | SMTP password or app-specific password |
| `ALERT_TO` | Yes | Recipient email address |
| `GITHUB_TOKEN` | No | GitHub PAT for higher rate limits (60 → 5000 req/hr) |

### 3. Run manually

```bash
./venv/bin/python3 ai_news_digest.py
```

### 4. Schedule with cron (daily at 7 AM)

```cron
0 7 * * * /opt/daily-news/venv/bin/python3 /opt/daily-news/ai_news_digest.py >> /var/log/ai_news.log 2>&1
```

---

## Requirements

- Python 3.10+
- `mistralai >= 1.0.0`
- `requests >= 2.31.0`

No other dependencies — the `.env` loader is built-in (no `python-dotenv` needed).

---

## Project Structure

```
mistral-security-digest/
├── ai_news_digest.py   # Main script — all logic in one file
├── requirements.txt     # Python dependencies
├── .env.example         # Template for .env (copy to .env)
├── .gitignore           # Excludes .env, venv/, __pycache__/
└── README.md            # This file
```

---

## API Usage & Costs

Per daily run (approximate):

| API | Calls | Notes |
|-----|-------|-------|
| Perplexity sonar-pro | 3 requests | AI news, WP vulns, infra vulns |
| OSV.dev | 1 batch request | Free, no API key needed |
| GitHub API | 1 + N requests | 1 commits list + N CVE JSON fetches (5000 req/hr with token, 60 without) |
| Mistral mistral-large-latest | 1 request | ~10K max tokens for formatting |
| SMTP | 1 email | Via your configured provider |

Typical execution time: **~45–55 seconds**.

---

## Customization

### Add/remove AI topics
Edit `AI_TOPICS` list in `ai_news_digest.py`.

### Add/remove monitored software
The default list covers common infrastructure (Ubuntu, Docker, Nginx, PHP, MariaDB, AWS, Azure, etc.), but you can add **any software** you use — databases, frameworks, CI/CD tools, cloud services, CMS platforms, or custom packages.

- **OSV.dev packages**: Edit `OSV_TARGETS` — each entry is `(display_name, ecosystem, package)`. Verify the ecosystem and package name exist at [osv.dev](https://osv.dev).
- **Perplexity-only targets**: Edit `PERPLEXITY_EXTRA_TARGETS` for packages not in OSV.dev (e.g., Windows 11).
- **CVE keyword matching**: Edit `CVE_KEYWORDS` to add/remove keywords matched against cvelistV5 entries.
- **WordPress routing**: CVEs matching `CVE_WP_KEYWORDS` go to the WordPress section instead of the CVE List section.

---

## License

MIT
