# dns-servers

A large, regularly-refreshed list of **public DNS resolvers that actually recurse, don't
hijack, and don't filter** — for bulk resolution (massdns and friends), where a poisoned or
filtering resolver silently corrupts millions of answers. MIT.

**`nameservers.txt`** is the list: every IP passed live probing at the last refresh, one per
line, sorted, IPv4.

## How the list is built

Most public resolver lists reuse the same curated feed. This one starts wider: it examines the
**authoritative NS records of 500M+ domains** and resolves those nameserver hostnames to IPs. A
small fraction of those machines happen to answer recursive queries for anyone, and almost none
of them appear in the curated feeds — so this surfaces thousands of working resolvers the public
lists have never seen. The [public-dns.info](https://public-dns.info) pool
(`reliability >= 0.99`) is folded in as an additional seed.

Discovery only nominates candidates. Membership in `nameservers.txt` is decided by probing every
one of them:

1. **Recursion.** Each probe domain must return `NOERROR`, at least one answer, and the `RA`
   flag, within the timeout. No `RA` means it won't recurse for you.
2. **No hijacking.** A random non-existent domain must *not* resolve. Resolvers that monetise
   `NXDOMAIN` with an ad page fail here.
3. **No filtering.** Live canary hosts from the [URLhaus](https://urlhaus.abuse.ch) malware feed
   must not come back `NXDOMAIN`, empty, or pointing at a known sinkhole range. A filtering
   resolver silently deletes real answers from a crawl.

Gates 2 and 3 are skipped for a run (rather than failing everything) if the control resolvers or
canary feed are unreachable — a bad run should shrink the list, never poison it.

Validation runs off-CI, because it needs a network that permits bulk outbound UDP:53.
GitHub-hosted runners do not — they time out on ~98% of resolvers — so nothing here is validated
by an Action. Rebuild from a host with real DNS egress using the commands below.

## Use the list

Fetch the raw file; the IPs are one per line, sorted, IPv4:

```
https://raw.githubusercontent.com/yudelevi/dns-servers/main/nameservers.txt
```

## Rebuild it yourself

The included tool rebuilds a validated list from the public-dns.info seed (the discovery half
runs against a private crawl and is not part of this repo):

```bash
uv sync
uvx pre-commit install                                   # format/lint gate before commits
uv run refresh-nameservers                               # public-dns.info pool -> validated list
uv run validate-resolvers --input my-list.txt --output validated.txt
uv run validate-resolvers --input pool.txt --extra more-candidates.txt --output validated.txt
```

`validate-resolvers` is also a library (`dns_servers.validate.validate`) if you keep your own
candidate pool and just want the probing. Exit codes: `2` pass rate under the floor, `3` input
older than `--max-input-age-days` (output still written, so a monitor can see a dead refresh),
`4` survivor count collapsed to under half the previous run.

## Provenance

Resolver IP addresses are facts, not authorship, and this repo asserts no ownership over them.
The public-dns.info seed pool is published by [public-dns.info](https://public-dns.info). The
code is original and MIT-licensed — see `LICENSE`.
