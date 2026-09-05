# Known Limitations

- Prototype testing is performed using Linux disk images; physical pendrive testing is pending.
- pytsk3, Scalpel, and Foremost have been independently tested with PNG recovery.
- JPG and PDF recovery have been tested through pytsk3 and Scalpel.
- Foremost JPG/PDF recovery has been tested through the recovery wrapper.
- Confidence reflects artifact validity and integrity, not guaranteed completeness of carved data.
- A HIGH confidence score does not guarantee that a carved artifact is completely recovered.
- Post-sanitization validation means no qualifying artifacts were detected by the implemented recovery engines; it does not prove physical impossibility of data recovery.
- SHA-256 deduplication detects byte-identical recovery outputs; different carves of the same underlying artifact can have different hashes and are not deduplicated.
- Cross-engine artifact matching based on byte-range overlap or similarity is a future improvement and is outside the prototype scope.
