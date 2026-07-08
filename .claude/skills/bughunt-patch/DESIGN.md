## Testing this skill

Static mode against the canary fixture:

```
/bughunt-vuln-scan targets/canary
/bughunt-triage VULN-FINDINGS.json --repo targets/canary --auto
/bughunt-patch TRIAGE.json --repo targets/canary --top 3
```

Expected: three diffs under `PATCHES/bug_00..02/`, each
`verified: "static_review_only"`, `review: ACCEPT`, style ≥ 7 for the
planted overflow/UAF/format-string bugs.

Execution-verified mode against pipeline output:

```
vuln-pipeline run drlibs --runs 3 --parallel --stream --model <m>
/bughunt-patch results/drlibs/<ts>/ --model <m>
```

Expected: delegates to `vuln-pipeline patch`, surfaces
`verified: "ladder_passed"` per bug, copies diffs into `./PATCHES/`.

---

## Design notes

- **TRIAGE.json is canonical input** because patching unverified findings
  wastes tokens on false positives. VULN-FINDINGS.json is accepted with a
  warning for convenience.
- **Static mode emits a regression test inside the diff** rather than
  running it. The skill cannot execute target code (constraint of the
  static pipeline); the test is for the human who applies the diff.
- **Reviewer never sees finding prose.** Target source can contain
  injected instructions that survive into a scanner's `description` field.
  The patch author sees that prose (it has to, to know what to fix); the
  reviewer doesn't, so injected text cannot pass its own gate.
- **`verified` is the verification class, not pass/fail.**
  `static_review_only` means "an agent read it" regardless of
  ACCEPT/REJECT. `ladder_passed`/`ladder_failed` means "ASAN decided."
  Downstream tooling should branch on this field, not on `review`.
- **Output shape matches the pipeline** (`PATCHES/bug_NN/{patch.diff,
  patch_result.json}`) so consumers don't care which mode produced it.
