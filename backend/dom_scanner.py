import asyncio
import logging
import uuid
from typing import Dict, Any
from urllib.parse import urlparse, urlunparse
from sqlalchemy.orm import Session
from playwright.async_api import async_playwright, TimeoutError
from models import Finding

logger = logging.getLogger("DOMScanner")

def build_test_url(base_url: str, payload: str) -> str:
    """Safely merges query parameters or fragment payloads into an existing URL structure."""
    parsed = urlparse(base_url)
    if payload.startswith("?"):
        param_str = payload[1:]
        new_query = f"{parsed.query}&{param_str}" if parsed.query else param_str
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
    elif payload.startswith("#"):
        frag_str = payload[1:]
        new_frag = f"{parsed.fragment}&{frag_str}" if parsed.fragment else frag_str
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, new_frag))
    else:
        return f"{base_url.rstrip('/')}/{payload.lstrip('/')}"


async def run_dom_scan(db: Session, target_id: int, url: str) -> Dict[str, Any]:
    """
    Evaluates client-side DOM vulnerabilities including Prototype Pollution
    and DOM-based Cross-Site Scripting (XSS) via headless browser execution.
    """
    logger.info(f"[*] Starting headless DOM scanner for {url}")
    results = {"url": url, "status": "secure", "findings": []}

    # Generate unique, dynamic canary tokens per execution run
    canary_key = f"pp_{uuid.uuid4().hex[:8]}"
    canary_value = f"val_{uuid.uuid4().hex[:8]}"
    xss_canary_token = f"xss_{uuid.uuid4().hex[:8]}"

    pp_payloads = [
        f"?__proto__[{canary_key}]={canary_value}",
        f"?constructor[prototype][{canary_key}]={canary_value}",
        f"#{canary_key}={canary_value}&__proto__[{canary_key}]={canary_value}"
    ]

    async with async_playwright() as p:
        try:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                ignore_https_errors=True,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) My_Scanner_DOM_Engine"
            )

            # --- Step 1: Baseline Check ---
            baseline_page = await context.new_page()
            try:
                await baseline_page.goto(url, timeout=15000, wait_until="domcontentloaded")
                is_baseline_tainted = await baseline_page.evaluate(
                    f"() => Object.prototype.hasOwnProperty('{canary_key}')"
                )
                if is_baseline_tainted:
                    logger.warning(f"[!] Baseline check failed for {url}: Canary key already present.")
                    await baseline_page.close()
                    await browser.close()
                    return results
            except Exception as e:
                logger.error(f"Failed baseline check for {url}: {e}")
            finally:
                await baseline_page.close()

            # --- Step 2: Prototype Pollution Evaluation ---
            for payload in pp_payloads:
                test_url = build_test_url(url, payload)
                page = await context.new_page()
                page.on("dialog", lambda dialog: dialog.accept())

                try:
                    await page.goto(test_url, timeout=15000, wait_until="domcontentloaded")
                    await page.wait_for_timeout(1000)

                    is_polluted = await page.evaluate(
                        f"() => ({{}}).{canary_key} === '{canary_value}'"
                    )

                    if is_polluted:
                        logger.warning(f"[!] Verified Prototype Pollution: {test_url}")
                        results["status"] = "vulnerable"

                        existing = db.query(Finding).filter(
                            Finding.target_id == target_id,
                            Finding.title == "Client-Side Prototype Pollution",
                            Finding.endpoint == test_url
                        ).first()

                        if not existing:
                            finding = Finding(
                                target_id=target_id,
                                title="Client-Side Prototype Pollution",
                                severity="high",
                                endpoint=test_url,
                                draft_report=(
                                    f"### Verified Client-Side Prototype Pollution\n\n"
                                    f"**Target URL**: `{test_url}`\n"
                                    f"**Payload**: `{payload}`\n"
                                    f"**Verification Result**: `Object.prototype.{canary_key}` successfully populated with `{canary_value}`.\n\n"
                                    f"**Remediation**: Freeze `Object.prototype` using `Object.freeze(Object.prototype)` or sanitize query/hash key parser logic."
                                ),
                                is_verified=True
                            )
                            db.add(finding)
                            db.commit()

                        results["findings"].append({"type": "prototype_pollution", "url": test_url})
                        await page.close()
                        break

                except TimeoutError:
                    logger.debug(f"Timeout loading {test_url}")
                except Exception as e:
                    logger.error(f"Error checking {test_url}: {e}")
                finally:
                    await page.close()

            # --- Step 3: DOM-based XSS Sink Evaluation ---
            dom_xss_url = build_test_url(url, f"#{xss_canary_token}")
            xss_page = await context.new_page()

            # Inject expanded sink monitoring hooks before scripts run
            sink_hook_script = f"""
                window.__dom_xss_detected = false;
                window.__dom_xss_sink = '';
                const canary = '{xss_canary_token}';

                function checkAndFlag(val, sinkName) {{
                    if (typeof val === 'string' && val.includes(canary)) {{
                        window.__dom_xss_detected = true;
                        window.__dom_xss_sink = sinkName;
                    }}
                }}

                // 1. Hook innerHTML
                const origInnerHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML').set;
                Object.defineProperty(Element.prototype, 'innerHTML', {{
                    set: function(val) {{
                        checkAndFlag(val, 'Element.innerHTML');
                        return origInnerHTML.call(this, val);
                    }}
                }});

                // 2. Hook document.write
                const origWrite = document.write;
                document.write = function(val) {{
                    checkAndFlag(val, 'document.write');
                    return origWrite.apply(this, arguments);
                }};

                // 3. Hook eval
                const origEval = window.eval;
                window.eval = function(val) {{
                    checkAndFlag(val, 'window.eval');
                    return origEval.apply(this, arguments);
                }};
            """
            await xss_page.add_init_script(sink_hook_script)

            try:
                await xss_page.goto(dom_xss_url, timeout=15000, wait_until="domcontentloaded")
                await xss_page.wait_for_timeout(1000)

                xss_triggered = await xss_page.evaluate("() => window.__dom_xss_detected || false")
                sink_name = await xss_page.evaluate("() => window.__dom_xss_sink || 'Unknown Sink'")

                if xss_triggered:
                    logger.warning(f"[!] Verified DOM-based XSS Sink execution on {dom_xss_url}")
                    results["status"] = "vulnerable"

                    existing = db.query(Finding).filter(
                        Finding.target_id == target_id,
                        Finding.title == "DOM Scanner: Verified DOM-Based Cross-Site Scripting (XSS)",
                        Finding.endpoint == dom_xss_url
                    ).first()

                    if not existing:
                        finding = Finding(
                            target_id=target_id,
                            title="DOM Scanner: Verified DOM-Based Cross-Site Scripting (XSS)",
                            severity="high",
                            endpoint=dom_xss_url,
                            draft_report=(
                                f"### Verified DOM XSS Finding\n\n"
                                f"**Target URL**: `{dom_xss_url}`\n"
                                f"**Source**: `location.hash` / `location.search`\n"
                                f"**Sink**: `{sink_name}`\n"
                                f"**Verification Result**: Source value containing canary token `{xss_canary_token}` dynamically reached dangerous sink `{sink_name}`.\n\n"
                                f"**Remediation**: Use `textContent` or context-aware escaping libraries rather than raw string insertion into DOM sinks."
                            ),
                            is_verified=True
                        )
                        db.add(finding)
                        db.commit()

                    results["findings"].append({"type": "dom_xss", "url": dom_xss_url, "sink": sink_name})

            except TimeoutError:
                logger.debug(f"Timeout evaluating DOM XSS on {dom_xss_url}")
            except Exception as e:
                logger.error(f"Error during DOM XSS evaluation: {e}")
            finally:
                await xss_page.close()

            await browser.close()

        except Exception as e:
            logger.error(f"Playwright execution error: {e}")
            results["status"] = "error"

    return results