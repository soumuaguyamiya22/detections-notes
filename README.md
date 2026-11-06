# detections-notes

Notes on the part of the job that comes *after* triage: turning a single sample
into a detection I can actually ship. Each writeup starts from real static or
behavioural evidence and walks through to a rule — YARA on disk, Sigma on the
wire or on the host — with the reasoning for every line, because the reasoning
is the part that doesn't transfer from a copied rule.

- [From strings to a YARA rule](yara-from-strings.md) — a macOS Mach-O stealer,
  and how I get from its distinctive strings to a rule that's precise instead of
  noisy.
- [From behaviour to a Sigma rule](sigma-from-behaviour.md) — a raw-IP `.php`
  beacon and a LaunchAgent persistence plist, turned into Sigma you can deploy
  and then tune.

## Why

I kept my sample teardowns and my detection rules in separate places and found I
was losing the bit in between — *why* a rule looks the way it does, which
strings I rejected, how I picked the condition that keeps it off clean software.
These notes are that middle step written down, so the next rule is faster.

The raw evidence comes from my triage tools: [macho-triage][macho] for the
first static pass over Mach-O samples (load commands, embedded strings,
embedded endpoints), and [plist-triage][plist] for the macOS launchd
persistence — the LaunchAgent / LaunchDaemon jobs that keep those stagers resident.

[macho]: https://github.com/soumuaguyamiya22/macho-triage
[plist]: https://github.com/soumuaguyamiya22/plist-triage

## Indicators

Every indicator in these notes is synthetic — RFC 5737 addresses
(`203.0.113.0/24`, `198.51.100.0/24`), `example.com`, and placeholder hashes. If
you reproduce a rule, drop in your own sample's values.

## License

MIT
