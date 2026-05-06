# CookieSniffer

Web crawler for cookie tracking and privacy contact extraction with multi-language support.

## Features

- **Cookie Tracking**: Captures all website cookies with detailed metadata
- **Privacy Contact Extraction**: Automatically finds privacy-related emails, forms, and links (GDPR/CCPA compliance contacts)
- **Language Detection**: 6-method weighted voting system for accurate language detection
- **Multi-language Support**: Keyword matching for 10+ languages (EN, ES, FR, DE, IT, PT, NL, AR, PL, SV, DA, etc.)

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt
```
# CookieSniffer

Web crawler for cookie tracking and privacy contact extraction with multi-language support.

## Features

- **Cookie Tracking**: Captures website cookies with detailed metadata.
- **Privacy Contact Extraction**: Finds privacy-related emails, forms, and links (GDPR/CCPA contacts).
- **Language Detection**: 6-method weighted voting system for improved detection.
- **Multi-language Support**: Keyword matching for many languages (EN, ES, FR, DE, IT, PT, NL, AR, PL, SV, DA, etc.).

## Quick Start

```bash
# Create and activate virtualenv (optional but recommended)
python -m venv env
source env/bin/activate

# Install dependencies
pip install -r requirements.txt

# Full crawl (cookies + privacy contacts + analysis)
python cli.py -u example.com -t 30

# Privacy contacts only 
python run_contact_scraper.py -d example.com -o contacts.csv

# GDPR data analysis
python Sec_GDPR_Right_DataAnalysis.py -i data/google_de.json -o cleaned.csv

````

## Command Options

### Main Crawler (`cli.py`)

- `-u URL`: Single URL to crawl
- `-uc CATEGORY`: Crawl URLs from a predefined category (eu/usa)
- `-t SECONDS`: Time to spend per website (default: 60)
- `-p DIR`: Profiles directory (default: `./profiles`)
- `-ch`: Use Chromium browser
- `-vpn`: Use ProtonVPN
- `--no-contact-scraper`: Disable privacy contact extraction

### Contact Scraper (`run_contact_scraper.py`)

- `-d DOMAIN`: Domain to scrape
- `-f FILE`: File with domain list
- `-o FILE`: Output CSV file
- `--top-picks`: Save top N findings per domain

### GDPR Data Analysis (`Sec_GDPR_Right_DataAnalysis.py`)

- `-i PATH`: Input JSON file or folder
- `-d DIR`: Directory of JSON files to aggregate
- `-o FILE`: Output CSV file path

## Project Structure

```
CookieSniffer/
├── cli.py
├── crawler.py
├── run_contact_scraper.py
├── helpers/
├── data/
├── profiles/
└── logs/
```

## Configuration

Edit `helpers/contact_scraper_config.py` to customize candidate paths, keywords, scoring weights, and extraction methods.

## Output

- Cookie data: `profiles/[domain]/data.json`
- Privacy contacts (per-domain): `profiles/[domain]/privacy_contacts_[domain].csv`
- Aggregated contacts: `privacy_contacts_aggregated.csv`

CSV columns include: domain, page_url, found_type, value, anchor_text, context_snippet, relevance_score, status_code, note, detected_language, language_confidence

## Prerequisites

- Python 3.7+
- Chrome/Chromium browser
- Selenium WebDriver
- Optional: ProtonVPN for VPN support

Configure paths in `helpers/essentials.py` (for example, `chromium_path` and `vpn_path`).

## Project Status

- Status: Active research prototype. Functionality for crawling, cookie collection, and contact extraction exists, but some scripts and paths may be experimental. Use a virtualenv and test on a small set of domains first.

## Contributing

- Issues and pull requests welcome. For code changes, please:
  1.  Fork the repo
  2.  Create a feature branch
  3.  Add tests if applicable
  4.  Open a PR with a description of changes

If you want, I can add a short CONTRIBUTING.md and run a quick tests script.

## License

See LICENSE file for details. (to be added later)
