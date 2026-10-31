# data/

Downloaded and derived data lives here and is **never committed** (see `.gitignore`).
The scripts that build it are in `src/phish_triage/data/`; sources,
licenses and counts are documented in [`docs/DATA.md`](../docs/DATA.md).

```
data/raw/        downloads, exactly as fetched (checksummed)
data/interim/    parsed records, masked records, duplicate list, index
data/splits/     split ids (fixed seeds) and their counts
```
