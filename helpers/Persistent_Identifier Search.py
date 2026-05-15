import pandas as pd
import re
from urllib.parse import urlparse

# -------- regexes --------
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
UUID  = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
TOKEN = re.compile(r"eyJ[A-Za-z0-9_-]+")  # basic JWT prefix pattern


def classify_party(request_host: str, first_party_domain: str) -> str:
    """Rough first-party vs third-party classifier."""
    if not isinstance(request_host, str) or not request_host:
        return "unknown"
    h = request_host.lower()
    fp = first_party_domain.lower()

    # treat subdomains as first-party too
    if h == fp or h.endswith("." + fp):
        return "first-party"
    return "third-party"


def extract_ids(text):
    ids = set()
    if not isinstance(text, str) or not text:
        return ids
    ids |= set(EMAIL.findall(text))
    ids |= set(UUID.findall(text))
    ids |= set(TOKEN.findall(text))
    return ids


def build_occurrence_index(csv_path, first_party_domain: str):
    """
    Returns:
      ids_set: all IDs found anywhere
      occ_df: table of occurrences (id, where_found, request_host, party, request_url, sample)
    """
    df = pd.read_csv(csv_path, dtype=str, keep_default_na=False)

    # Columns we will search. Add more if your CSV has them.
    SEARCH_COLS = [
        ("request_url", "url"),
        ("request_body_trunc", "request_body"),
        ("response_body_trunc", "response_body"),
        # If you later export cookie header / request headers to a column, include it here:
        ("request_cookie_header", "cookie_header"),
        ("request_headers", "request_headers"),
    ]

    # Keep only columns that actually exist
    SEARCH_COLS = [(c, label) for (c, label) in SEARCH_COLS if c in df.columns]

    # Make sure host column exists
    if "request_host" not in df.columns and "request_url" in df.columns:
        # derive host from URL if missing
        df["request_host"] = df["request_url"].apply(lambda u: urlparse(u).netloc.lower() if isinstance(u, str) else "")

    occurrences = []
    all_ids = set()

    for idx, row in df.iterrows():
        request_url = row.get("request_url", "")
        request_host = row.get("request_host", "")
        party = classify_party(request_host, first_party_domain)

        for col, where_label in SEARCH_COLS:
            text = row.get(col, "")
            found = extract_ids(text)
            if not found:
                continue

            # keep evidence
            for _id in found:
                all_ids.add(_id)

                # store a short sample (helpful for debugging)
                sample = text
                if isinstance(sample, str) and len(sample) > 250:
                    sample = sample[:250] + "...[trunc]"

                occurrences.append({
                    "id": _id,
                    "where_found": where_label,
                    "request_host": request_host,
                    "party": party,
                    "request_url": request_url,
                    "row_index": idx,
                    "sample": sample
                })

    occ_df = pd.DataFrame(occurrences)
    return all_ids, occ_df


def analyze_persistence(before_csv, after_csv, first_party_domain: str, out_csv="persistent_id_evidence.csv"):
    before_ids, before_occ = build_occurrence_index(before_csv, first_party_domain)
    after_ids, after_occ   = build_occurrence_index(after_csv, first_party_domain)

    common = before_ids & after_ids

    print("Before IDs:", len(before_ids))
    print("After IDs:", len(after_ids))
    print("Persisting IDs:", len(common))
    print("Persisting set:", common)

    if not common:
        print("\nNo persistent identifiers found.")
        return

    # Collect evidence rows from BEFORE and AFTER for those IDs
    before_e = before_occ[before_occ["id"].isin(common)].copy()
    before_e["phase"] = "before"

    after_e = after_occ[after_occ["id"].isin(common)].copy()
    after_e["phase"] = "after"

    evidence = pd.concat([before_e, after_e], ignore_index=True)

    # Helpful summary columns for Q1/Q2
    summary = (evidence
               .groupby(["id", "phase"])
               .agg(
                    where_found=("where_found", lambda x: ", ".join(sorted(set(x)))),
                    parties=("party", lambda x: ", ".join(sorted(set(x)))),
                    hosts=("request_host", lambda x: ", ".join(sorted(set(x)))),
                    examples=("request_url", lambda x: " | ".join(list(dict.fromkeys(x))[:5]))  # first 5 unique
               )
               .reset_index()
              )

    print("\n--- Summary (answers Q1/Q2) ---")
    for _, r in summary.iterrows():
        print(f"\nID: {r['id']}  ({r['phase']})")
        print("  where_found:", r["where_found"])
        print("  parties:", r["parties"])
        print("  hosts:", r["hosts"])
        print("  example_urls:", r["examples"])

    # Save full evidence (for your paper appendix / debugging)
    evidence.to_csv(out_csv, index=False, encoding="utf-8")
    print(f"\nSaved evidence rows to: {out_csv}")


if __name__ == "__main__":
    BEFORE = r"D:\Sec_GDPR\Sec_GDPR_Code_Final\Baseline Crawl\profiles\manomano_fr\network_requests_baseline.csv"
    AFTER  = r"D:\Sec_GDPR\Sec_GDPR_Code_Final\CookieSniffer-main\profiles\manomano_fr\network_requests_After.csv"

    # IMPORTANT: set this to the domain you consider first-party for this crawl
    FIRST_PARTY_DOMAIN = "lequipe.fr"

    analyze_persistence(BEFORE, AFTER, FIRST_PARTY_DOMAIN, out_csv="manomano_persistent_id_evidence.csv")
