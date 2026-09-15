# LLM Evaluation Fixture Safety

Files below `crates/aurscan-llm/tests/fixtures/semantic-malicious`, `paired`, and `injection` are malicious recipe **text fixtures**. No fixture is executable or supported for execution: never source one, run `makepkg` in its directory, build or install it, or invoke one of its hooks.

Automated checks may only read and decode fixture bytes as static data. They never source, build, install, or execute a recipe or hook. Network destinations have no literal fallback and require environment variables that are unset during validation. Privileged writes and service actions textually follow required environment-variable guards that are likewise unset during validation. These fail-safe guards reduce accidental impact but do not make fixture execution supported.

Safety notices live here, in `corpus-manifest.json`, and in `ORACLE.md`, outside every model-facing recipe bundle.
