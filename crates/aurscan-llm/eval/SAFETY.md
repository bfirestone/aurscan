# LLM Evaluation Fixture Safety

Files below `crates/aurscan-llm/tests/fixtures/semantic-malicious`, `paired`, and `injection` are malicious recipe **text fixtures**. Never source them, run `makepkg` in their directories, install them, or execute their hooks.

Automated tests may only read and submit their bytes as untrusted model input. Network examples use RFC-reserved `.invalid` destinations, decoded payloads are fixture markers, and local marker names are fixture-specific. These bounds reduce accidental impact but do not make executing the fixtures supported.

Safety notices live here and in `corpus-manifest.json`, outside model-facing recipe bundles, so evaluation input remains behaviorally faithful.
