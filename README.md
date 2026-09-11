# dns-servers

`nameservers.txt` — public DNS resolvers that were answering correctly the last time this
repo's workflow ran. Rebuilt weekly by GitHub Actions. MIT.

Intended for bulk resolution (massdns and friends), where a poisoned or filtering resolver
quietly corrupts millions of answers.

## What a resolver has to survive

Candidates come from the [public-dns.info](https://public-dns.info) pool, filtered to
`reliability >= 0.99` and globally routable addresses. Membership in `nameservers.txt` is
decided by probing, not by the feed:

1. **Recursion.** Every probe domain must come back `NOERROR`, with at least one answer
   and the `RA` flag set, inside the timeout. No `RA` means it will not recurse for you.
2. **No hijacking.** A random non-existent domain must *not* resolve. Resolvers that
   monetise `NXDOMAIN` with an ad landing page fail here.
3. **No filtering.** Live canary hosts drawn from the
   [URLhaus](https://urlhaus.abuse.ch) malware-URL feed must not come back `NXDOMAIN`,
   empty, or pointing at a known sinkhole range. A filtering resolver silently deletes
   real answers from a bulk resolution run.

Gates 2 and 3 are skipped for a run, rather than failing everything, if the control
resolvers or the canary feed are unreachable — a bad run should shrink the list, never
poison it.

Two floors protect the published file: the run aborts without writing if the pass rate
drops under 30%, or if the survivor count falls below half of the previous run.

## Freshness caveat

The upstream pool is a seed and nothing more. Its own `checked_at` stamps stopped moving
in **August 2023**, so the candidate set only shrinks over time; every liveness claim in
this repo comes from our own probe, and `nameservers.meta.json` records the source's
newest stamp each run so the staleness stays visible. A second seed source is the obvious
next move if the survivor count drifts down.

## Use

```bash
uv sync
uvx pre-commit install    # format/lint gate before every commit
uv run refresh-nameservers                      # rebuild nameservers.txt end to end
uv run refresh-nameservers --limit 500 --dry-run
uv run validate-resolvers --input my-list.txt --output validated.txt
```

`validate-resolvers` also works as a library (`dns_servers.validate.validate`) if you keep
your own candidate pool and just want the probing.

Exit codes: `2` pass rate under the floor, `3` input list older than
`--max-input-age-days` (output still written, so a monitor can see a dead refresh), `4`
survivor count collapsed.

## Provenance

Resolver IP addresses are facts, not authorship, and this repo asserts no ownership over
them; the candidate pool is published by public-dns.info and credited above. The code is
original and MIT-licensed — see `LICENSE`.
