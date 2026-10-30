# data/

Downloaded and derived data lives here and is **never committed** (see `.gitignore`).
The download and build scripts are in `scripts/` and `src/phish_triage/data/`; sources,
licenses and counts are documented in [`docs/DATA.md`](../docs/DATA.md).

```
data/raw/        downloads, exactly as fetched (checksummed)
data/interim/    parsed, unified records
data/processed/  de-duplicated, masked, split
```
