#!/usr/bin/env python3
import argparse
import asyncio
import json
import logging
import os
import re
import sqlite3
import sys
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import httpx

# Configure logging format
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("My_Scanner")


# =====================================================================
# DATABASE MANAGEMENT
# =====================================================================

def init_database(db_path: str):
    """
    Initializes the SQLite database and creates the findings table if missing.
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_url TEXT NOT NULL,
            vulnerability TEXT NOT NULL,
            severity TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            parameter TEXT,
            source TEXT NOT NULL,
            proof TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()
    logger.info(f"Database initialized: {db_path}")


def save_findings_to_db(db_path: str, findings: List[Dict[str, Any]], target_url: str):
    """
    Persists scan results into the SQLite database with deduplication.
    """
    if not findings:
        return

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    inserted_count = 0
    for item in findings:
        cursor.execute("""
            SELECT id FROM vulnerabilities 
            WHERE endpoint = ? AND vulnerability = ?
        """, (item.get("endpoint"), item.get("vulnerability")))
        
        if not cursor.fetchone():
            cursor.execute("""
                INSERT INTO vulnerabilities 
                (target_url, vulnerability, severity, endpoint, parameter, source, proof, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                target_url,
                item.get("vulnerability", "Unknown Issue"),
                item.get("severity", "Info"),
                item.get("endpoint", target_url),
                item.get("parameter", ""),
                item.get("source", "Unknown"),
                str(item.get("proof", ""))[:500],
                datetime.now(timezone.utc).isoformat()
            ))
            inserted_count += 1

    conn.commit()
    conn.close()
    logger.info(f"Saved {inserted_count} new findings to database: {db_path}")


# =====================================================================
# REPORT EXPORT GENERATOR
# =====================================================================

def export_reports(findings: List[Dict[str, Any]], target_url: str, json_path: Optional[str], html_path: Optional[str]):
    """
    Exports findings to JSON and/or HTML reports if requested via CLI flags.
    """
    if json_path:
        try:
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump({
                    "target_url": target_url,
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "total_findings": len(findings),
                    "findings": findings
                }, f, indent=4)
            logger.info(f"Exported JSON report to: {json_path}")
        except Exception as e:
            logger.error(f"Failed to export JSON report: {e}")

    if html_path:
        try:
            rows = ""
            for idx, item in enumerate(findings, start=1):
                sev = item.get("severity", "Info").lower()
                badge_class = f"badge-{sev}" if sev in ["critical", "high", "medium", "low"] else "badge-info"
                rows += f"""
                <tr>
                    <td>{idx}</td>
                    <td><span class="badge {badge_class}">{item.get('severity')}</span></td>
                    <td><strong>{item.get('vulnerability')}</strong></td>
                    <td><code>{item.get('endpoint')}</code></td>
                    <td>{item.get('parameter') or 'N/A'}</td>
                    <td>{item.get('source')}</td>
                    <td><pre>{item.get('proof')}</pre></td>
                </tr>
                """

            html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Scan Report - {target_url}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 2rem; }}
        h1 {{ color: #38bdf8; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 1.5rem; background: #1e293b; border-radius: 8px; overflow: hidden; }}
        th, td {{ padding: 12px 16px; text-align: left; border-bottom: 1px solid #334155; }}
        th {{ background: #334155; color: #94a3b8; font-size: 0.85rem; text-transform: uppercase; }}
        code {{ background: #0f172a; padding: 2px 6px; border-radius: 4px; color: #f43f5e; }}
        pre {{ margin: 0; white-space: pre-wrap; font-size: 0.85rem; color: #cbd5e1; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 0.75rem; text-transform: uppercase; }}
        .badge-critical {{ background: #991b1b; color: #fecaca; }}
        .badge-high {{ background: #9a3412; color: #ffedd5; }}
        .badge-medium {{ background: #854d0e; color: #fef08a; }}
        .badge-low {{ background: #1e3a8a; color: #bfdbfe; }}
        .badge-info {{ background: #115e59; color: #ccfbf1; }}
    </style>
</head>
<body>
    <h1>Security Scan Report</h1>
    <p><strong>Target:</strong> {target_url} | <strong>Generated:</strong> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} | <strong>Total Findings:</strong> {len(findings)}</p>
    <table>
        <thead>
            <tr>
                <th>#</th>
                <th>Severity</th>
                <th>Vulnerability</th>
                <th>Endpoint</th>
                <th>Parameter</th>
                <th>Source</th>
                <th>Proof</th>
            </tr>
        </thead>
        <tbody>
            {rows if findings else '<tr><td colspan="7">No vulnerabilities discovered.</td></tr>'}
        </tbody>
    </table>
</body>
</html>"""

            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            logger.info(f"Exported HTML report to: {html_path}")
        except Exception as e:
            logger.error(f"Failed to export HTML report: {e}")


# =====================================================================
# TRACK 1: NUCLEI ENGINE SUBPROCESS
# =====================================================================

async def run_nuclei_subprocess(
    target_url: str, 
    custom_headers: Dict[str, str]
) -> List[Dict[str, Any]]:
    """
    Executes Nuclei CLI via async subprocess, parsing JSON stream output.
    """
    logger.info("[Track 1] Launching Nuclei scanner...")

    cmd = ["nuclei", "-u", target_url, "-jsonl", "-silent"]

    for key, value in custom_headers.items():
        cmd.extend(["-header", f"{key}: {value}"])

    findings = []
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await process.communicate()

        if stdout:
            for line in stdout.decode().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    findings.append({
                        "vulnerability": data.get("info", {}).get("name", "Nuclei Detection"),
                        "severity": data.get("info", {}).get("severity", "info").capitalize(),
                        "endpoint": data.get("matched-at", target_url),
                        "parameter": data.get("matcher-name", ""),
                        "source": "Nuclei",
                        "proof": data.get("extracted-results", [data.get("template-id")])[0] if data.get("extracted-results") else data.get("template-id")
                    })
                except json.JSONDecodeError:
                    continue

        logger.info(f"[Track 1] Nuclei scan complete. Discovered {len(findings)} items.")

    except FileNotFoundError:
        logger.warning("[Track 1] Nuclei binary not found in PATH. Skipping Nuclei track.")
    except Exception as e:
        logger.error(f"[Track 1] Nuclei execution error: {e}")

    return findings


# =====================================================================
# TRACK 2: NATIVE CUSTOM PYTHON ENGINES
# =====================================================================

async def check_reflected_xss(client: httpx.AsyncClient, target_url: str) -> Optional[Dict[str, Any]]:
    parsed = urllib.parse.urlparse(target_url)
    params = urllib.parse.parse_qs(parsed.query)
    if not params:
        return None

    canary = "xss31337"
    probe = f"'{canary}\"><svg/onload=alert(1)>"

    for param in params:
        test_params = params.copy()
        test_params[param] = probe
        new_query = urllib.parse.urlencode(test_params, doseq=True)
        fuzzed_url = urllib.parse.urlunparse(parsed._replace(query=new_query))

        try:
            res = await client.get(fuzzed_url)
            content_type = res.headers.get("Content-Type", "").lower()
            if res.status_code == 200 and probe in res.text and ("html" in content_type or "xml" in content_type):
                return {
                    "vulnerability": "Reflected Cross-Site Scripting (XSS)",
                    "severity": "High",
                    "endpoint": fuzzed_url,
                    "parameter": param,
                    "source": "My_Scanner_Native",
                    "proof": f"Reflected unescaped canary string in param: {param}"
                }
        except Exception:
            continue
    return None


async def check_cors_misconfig(client: httpx.AsyncClient, target_url: str) -> Optional[Dict[str, Any]]:
    evil_origin = "https://evil-attacker.com"
    try:
        res = await client.get(target_url, headers={"Origin": evil_origin})
        allow_origin = res.headers.get("Access-Control-Allow-Origin", "")
        allow_credentials = res.headers.get("Access-Control-Allow-Credentials", "").lower()

        if allow_origin == evil_origin and allow_credentials == "true":
            return {
                "vulnerability": "CORS Misconfiguration (Arbitrary Origin Trust with Credentials)",
                "severity": "Medium",
                "endpoint": target_url,
                "parameter": "Origin",
                "source": "My_Scanner_Native",
                "proof": f"Access-Control-Allow-Origin reflected {evil_origin} with Credentials: true"
            }
    except Exception:
        pass
    return None


async def check_error_sqli(client: httpx.AsyncClient, target_url: str) -> Optional[Dict[str, Any]]:
    parsed = urllib.parse.urlparse(target_url)
    params = urllib.parse.parse_qs(parsed.query)
    if not params:
        return None

    sql_regexes = [
        r"you have an error in your sql syntax",
        r"unclosed quotation mark after the character string",
        r"pg_query\(\): query failed",
        r"sqlite3::sqlexception",
        r"ora-[0-9]{5}"
    ]

    for param in params:
        test_params = params.copy()
        test_params[param] = f"{test_params[param][0]}'"
        new_query = urllib.parse.urlencode(test_params, doseq=True)
        fuzzed_url = urllib.parse.urlunparse(parsed._replace(query=new_query))

        try:
            res = await client.get(fuzzed_url)
            for pattern in sql_regexes:
                if re.search(pattern, res.text, re.IGNORECASE):
                    return {
                        "vulnerability": "Error-Based SQL Injection",
                        "severity": "Critical",
                        "endpoint": fuzzed_url,
                        "parameter": param,
                        "source": "My_Scanner_Native",
                        "proof": f"Matched database error pattern: {pattern}"
                    }
        except Exception:
            continue
    return None


async def run_custom_python_engines(
    target_url: str, 
    headers: Dict[str, str], 
    concurrency_limit: int
) -> List[Dict[str, Any]]:
    """
    Track 2: Executes native asynchronous security checks concurrently.
    """
    logger.info("[Track 2] Launching native Python vulnerability engines...")

    semaphore = asyncio.Semaphore(concurrency_limit)

    async with httpx.AsyncClient(headers=headers, timeout=10.0, verify=False) as client:
        async def wrap_check(coro):
            async with semaphore:
                return await coro

        tasks = [
            wrap_check(check_reflected_xss(client, target_url)),
            wrap_check(check_cors_misconfig(client, target_url)),
            wrap_check(check_error_sqli(client, target_url))
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

    findings = []
    for res in results:
        if isinstance(res, dict) and res is not None:
            findings.append(res)

    logger.info(f"[Track 2] Native scan complete. Discovered {len(findings)} items.")
    return findings


# =====================================================================
# MAIN PIPELINE & CLI ORCHESTRATOR
# =====================================================================

async def run_full_scan_pipeline(
    target_url: str, 
    db_path: str, 
    headers: Dict[str, str], 
    skip_nuclei: bool, 
    concurrency: int,
    export_json_path: Optional[str],
    export_html_path: Optional[str]
):
    """
    Orchestrates scan execution across all engines, deduplicates, saves to DB, and generates reports.
    """
    logger.info(f"Target Acquired: {target_url}")

    nuclei_task = run_nuclei_subprocess(target_url, headers) if not skip_nuclei else asyncio.sleep(0, result=[])
    custom_task = run_custom_python_engines(target_url, headers, concurrency)

    nuclei_results, custom_results = await asyncio.gather(nuclei_task, custom_task)

    all_findings = nuclei_results + custom_results

    # Print summary to console
    print("\n" + "=" * 60)
    print(f" SCAN RESULTS SUMMARY FOR: {target_url}")
    print("=" * 60)

    if not all_findings:
        print(" [✓] No vulnerabilities discovered.")
    else:
        for idx, finding in enumerate(all_findings, start=1):
            print(f" [{idx}] [{finding['severity']}] {finding['vulnerability']}")
            print(f"     Endpoint: {finding['endpoint']}")
            print(f"     Source:   {finding['source']}")
            if finding.get("parameter"):
                print(f"     Parameter:{finding['parameter']}")
            print("-" * 60)

    # Persist results to SQLite database
    save_findings_to_db(db_path, all_findings, target_url)

    # Export requested reports
    if export_json_path or export_html_path:
        export_reports(all_findings, target_url, export_json_path, export_html_path)


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="My_Scanner: Hybrid DAST Vulnerability Orchestrator"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="Single target URL to scan (e.g. https://example.com)")
    group.add_argument("-f", "--file", help="File containing list of target URLs")

    parser.add_argument("-db", "--database", default="scanner_results.db", help="SQLite DB output file (default: scanner_results.db)")
    parser.add_argument("-H", "--header", action="append", help="Custom HTTP headers (e.g. -H 'Authorization: Bearer <token>')")
    parser.add_argument("-c", "--concurrency", type=int, default=10, help="Max concurrency for native checks (default: 10)")
    parser.add_argument("--skip-nuclei", action="store_true", help="Skip running the Nuclei binary track")
    
    # Export reporting options
    parser.add_argument("--export-json", help="Export findings to a JSON report file (e.g. report.json)")
    parser.add_argument("--export-html", help="Export findings to an HTML report file (e.g. report.html)")

    return parser.parse_args()


def main():
    args = parse_arguments()

    headers = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                key, val = h.split(":", 1)
                headers[key.strip()] = val.strip()

    init_database(args.database)

    targets = []
    if args.url:
        targets.append(args.url)
    elif args.file:
        if os.path.exists(args.file):
            with open(args.file, "r") as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        else:
            logger.error(f"Target list file not found: {args.file}")
            sys.exit(1)

    for target in targets:
        asyncio.run(run_full_scan_pipeline(
            target_url=target,
            db_path=args.database,
            headers=headers,
            skip_nuclei=args.skip_nuclei,
            concurrency=args.concurrency,
            export_json_path=args.export_json,
            export_html_path=args.export_html
        ))


if __name__ == "__main__":
    main()