# Fuzz regression seeds

Inputs that once crashed a fuzz target, kept so the fuzzer starts from known-hard
cases rather than rediscovering them. Each is also asserted directly in a unit
test, so a regression fails `cargo test` without needing a fuzz run.

| Seed | Input | Bug it found |
|---|---|---|
| `purl/regression-1` | `PkG:F/k# /` | Subpath written unencoded; `parse` trims, so the canonical form reparsed to a PURL with no subpath. |
| `purl/regression-2` | `PkG:F/:%%2F/F` | A namespace segment decoding to contain `/` moved the segment boundaries on re-serialization. |
| `purl/regression-3` | `PkG:F/F#%2F` | Same class in the subpath: `%2F` decoded to a bare separator that flattened to nothing. |
| `purl/regression-4` | `PkG:F/%%%3333/Ff` | Double-decode. `pct::decode` is not idempotent (`%%333` → `%33` → `%3`), and the flatten helper decoded already-decoded input. |

All four broke the same property: **normalization must be idempotent**
(`parse(serialize(parse(s))) == parse(s)`). That property is not cosmetic —
graph node identity and the advisory cache are both keyed on the canonical
string, so an unstable normalization silently splits one package into two and
loses advisories for whichever half moved.

Fuzzer-generated corpus and crash artifacts are gitignored; only these are kept.
