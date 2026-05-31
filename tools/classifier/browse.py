#!/usr/bin/env python3
"""browse.py — charge une URL dans Chromium (Playwright) et liste les domaines contactés.

Usage : python3 browse.py <url> [--timeout MS] [--settle MS]

Enregistre un HAR de la navigation, en extrait les hôtes de toutes les requêtes
réseau, déduplique et imprime un tableau JSON sur stdout.

Robustesse : toute erreur (site injoignable, timeout) → impression de `[]` et
sortie en code 0, afin de ne pas casser le pipeline appelant (classifier.moon).

Le HAR temporaire est écrit sous ./tmp/ (jamais /tmp), conformément aux règles du
projet.
"""

import json
import os
import sys
import tempfile
from urllib.parse import urlparse


def extract_hosts(har_path):
    """Lit un fichier HAR et retourne l'ensemble trié des hôtes contactés."""
    with open(har_path, "r", encoding="utf-8") as fh:
        har = json.load(fh)
    hosts = set()
    for entry in har.get("log", {}).get("entries", []):
        url = entry.get("request", {}).get("url", "")
        host = urlparse(url).hostname
        if host:
            hosts.add(host.lower())
    return sorted(hosts)


def browse(url, timeout_ms, settle_ms):
    """Navigue sur url et retourne la liste des hôtes contactés (ou [] en cas d'échec)."""
    # Le HAR doit vivre dans ./tmp/ (cf. AGENTS.md : jamais /tmp).
    tmp_dir = os.path.join(os.getcwd(), "tmp")
    os.makedirs(tmp_dir, exist_ok=True)

    from playwright.sync_api import sync_playwright

    fd, har_path = tempfile.mkstemp(suffix=".har", dir=tmp_dir)
    os.close(fd)
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(record_har_path=har_path)
            page = context.new_page()
            try:
                page.goto(url, wait_until="load", timeout=timeout_ms)
                # Laisse le temps aux requêtes asynchrones (analytics, pubs, lazy-load).
                page.wait_for_timeout(settle_ms)
            except Exception as exc:  # noqa: BLE001 — on tolère tout échec de navigation
                sys.stderr.write(f"[browse] navigation partielle sur {url}: {exc}\n")
            finally:
                # close() flushe le HAR sur le disque.
                context.close()
                browser.close()
        return extract_hosts(har_path)
    finally:
        try:
            os.remove(har_path)
        except OSError:
            pass


def main(argv):
    if len(argv) < 2:
        sys.stderr.write("usage: browse.py <url> [--timeout MS] [--settle MS]\n")
        return 2
    url = argv[1]
    timeout_ms = 30000
    settle_ms = 3000
    i = 2
    while i < len(argv):
        if argv[i] == "--timeout" and i + 1 < len(argv):
            timeout_ms = int(argv[i + 1])
            i += 2
        elif argv[i] == "--settle" and i + 1 < len(argv):
            settle_ms = int(argv[i + 1])
            i += 2
        else:
            i += 1

    try:
        hosts = browse(url, timeout_ms, settle_ms)
    except Exception as exc:  # noqa: BLE001 — dernier filet : ne jamais crasher l'appelant
        sys.stderr.write(f"[browse] échec total sur {url}: {exc}\n")
        hosts = []

    sys.stdout.write(json.dumps(hosts))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
