# targets/

Drop codebases you want to scan here (clone, symlink, or copy them in).
This directory is otherwise empty — the skill docs' examples
(`targets/canary`, `targets/drlibs`, `targets/alsa`, ...) assume a target
lives at a path like this, but any path works: `/threat-model`,
`/vuln-scan`, and `/triage` all take `<target-dir>` as an argument.

Everything under here except this file is gitignored, so you can drop in
whatever you're auditing without polluting the repo's history.

```
/threat-model bootstrap targets/<your-target>
/vuln-scan targets/<your-target>
/triage VULN-FINDINGS.json --repo targets/<your-target>
```
