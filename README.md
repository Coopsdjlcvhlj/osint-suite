# osint-suite

One CLI in front of the OSINT tools already installed on this machine:
theHarvester, sherlock, amass, holehe, spiderfoot, shodan (CLI), recon-ng,
whois, dnsrecon, phonenumbers, phoneinfoga.

It doesn't reimplement anything — it shells out to each tool's real binary,
normalizes where results land, and writes a combined `report.json` /
`report.md` per run.

## Requirements

The tools themselves are installed via pacman/yay, not by this project:

```
sudo pacman -S theharvester-git sherlock-git amass holehe spiderfoot shodan recon-ng whois python-phonenumbers
yay -S python-dnsrecon phoneinfoga-bin   # AUR
```

Check what's actually on PATH:

```
python3 -m osint_suite list-tools
```

`shodan` needs a one-time `shodan init <API_KEY>`. `spiderfoot`'s passive
scan and `amass`'s default passive enum need no API keys; more sources
activate if you configure keys in their own config files.

## Usage

No install step required — run as a module from the project root:

```
python3 -m osint_suite domain example.com
python3 -m osint_suite domain example.com --tools whois dnsrecon
python3 -m osint_suite username johndoe
python3 -m osint_suite email person@example.com
python3 -m osint_suite phone +14155552671
python3 -m osint_suite phone +14155552671 --deep
python3 -m osint_suite spiderfoot example.com --use-case footprint
python3 -m osint_suite shodan host 1.1.1.1
python3 -m osint_suite recon myworkspace --resource-file ./recon.rc
python3 -m osint_suite all example.com --type domain --spiderfoot
```

Optionally install it as an `osint` command in a venv:

```
python3 -m venv .venv --system-site-packages
.venv/bin/pip install -e .
.venv/bin/osint list-tools
```

(`--system-site-packages` lets the venv see the pacman-installed tool
libraries; the wrappers themselves only call the installed binaries, so this
is not required — it's just handy if you also want to `import` theHarvester
etc. directly.)

## Results layout

Every run creates:

```
osint-results/<sanitized-target>/<UTC-timestamp>/
  <tool>/stdout.log, stderr.log, and the tool's own output files
  report.json   -- machine-readable manifest of every tool run
  report.md     -- human-readable summary
```

## Telegram self-exposure audit

`telegram-self-audit` checks how exposed *your own* Telegram account is —
not someone else's. It logs into your own account (official MTProto API via
Telethon) and reads your own privacy rules and active sessions: whether
strangers can find you by phone number (the exact mechanism contact-import
"probiv" bots rely on), who can see your phone/photo/last-seen, and whether
any unfamiliar device has an active session.

Setup (one-time):

1. `.venv/bin/pip install telethon` (already installed if you used the venv
   from the section above).
2. Get your own `api_id`/`api_hash` from https://my.telegram.org/apps
   (log in with your own number — these credentials are yours, don't share
   them).
3. Run it in an interactive terminal — the first run texts you a login code:

```
osint telegram-self-audit --api-id 123456 --api-hash abcdef0123456789abcdef0123456789
```

The session is cached at `~/.config/osint-suite/telegram_self_audit.session`
(outside the repo, gitignored by location) so later runs don't prompt again.
Delete that file to log out.

This only ever touches the account you log in as — it does not accept a
target phone number or username to look up, by design.

## Recon-ng

recon-ng is module- and workspace-driven and normally interactive. This
project only wraps its non-interactive batch mode: write a `.rc` file with
the commands you'd type inside the shell (`modules load ...`, `options set
...`, `run`) and pass it via `--resource-file`. For exploration, just run
`recon-ng -w <workspace>` directly.

## Pivoting (auto-chaining discoveries)

`osint pivot <target> --type {domain,phone}` is an event-driven mode: instead
of running each tool once against the seed and stopping, it also feeds
whatever new entities a tool turns up (subdomains, emails, IPs, a validated
phone number) into whichever *other* tools consume that entity type, and
keeps going breadth-first up to `--depth` hops.

```
python3 -m osint_suite pivot example.com --type domain          # depth 1, max 15 events
python3 -m osint_suite pivot example.com --type domain --depth 2 --max-events 40
python3 -m osint_suite pivot +14155552671 --type phone           # phonenumbers -> phoneinfoga if valid
```

Wiring, for `--type domain`: `theharvester`/`amass`/`dnsrecon`/`spiderfoot`
run against the seed domain and any emails/IPs/subdomains they find get
queued; subdomains feed back into `dnsrecon` (and `whois` for the apex domain
only — subdomains aren't independently WHOIS-registrable); emails feed into
`holehe`. For `--type phone`: `phonenumbers` validates the number, and only
if it's valid does `phoneinfoga` run against it.

Safety rails: subdomain/domain pivots stay inside the seed domain's own
scope unless you pass `--allow-external`, and `--max-events` (default 15)
caps how many entities actually get processed — a busy domain can turn up
thousands of candidate subdomains, most of them noise, so the cap is there to
stop that from becoming thousands of automatic follow-up requests. When the
cap is hit, the run tells you how many discovered entities were left
unprocessed. Restrict to specific modules with `--modules theharvester
dnsrecon` etc.

Every run writes `pivot-graph.md`/`pivot-graph.json` alongside the usual
`report.md`/`report.json`, showing which module ran against which discovered
entity and at what depth.

## Scope

Only use this against targets you're authorized to investigate (your own
assets, a scoped engagement, or an explicit CTF/research target).
