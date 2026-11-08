# BLEU reference corpora

`cmd_known.corpus` contains 167 Windows references and `bash_known.corpus`
contains 137 Linux references. These are static detection examples; the scanner
tokenizes them and never executes them. Each unique reference occupies one UTF-8
line, contains 10–95 characters, and produces at least four tokens using the
project's platform tokenizer. Four whitespace-separated words alone do not
describe this tokenizer's behavior, especially for quoted shell expressions.

The expanded collection adapts technique families documented by
[LOLBAS](https://lolbas-project.github.io/) and
[GTFOBins](https://gtfobins.org/), alongside eligible references from the original
corpora. New remote examples use `example.com` or `192.0.2.10`. These are
representative templates, not independently executed or validated exploits.
Some require existing scripts, DLLs, archives, elevated permissions, older tool
versions, or particular application layouts.

Windows coverage includes download cradles (`certutil`, BITS, PowerShell),
scriptlet execution (`regsvr32`, WSH, MSHTA), NTFS alternate data streams,
process-memory dumps (`procdump`, `comsvcs`, `sqldumper`, `adplus`), registry
hive exports, proxy DLL execution, .NET loaders, task/service persistence,
reverse shells, and DLL search-order placement followed by application launch.
DLL placement examples represent the observable preparation and launch steps;
an application's actual DLL search behavior determines whether sideloading occurs.

Linux coverage includes reverse/bind shells, download pipelines, editor and
interpreter shell escapes, archive hooks, SSH proxy commands, package-manager
hooks, preload/library paths, container host mounts, privilege preservation,
sensitive-file access, exfiltration, and scheduled execution.

References that violated the length/token constraints were removed or replaced
with eligible forms (for example, CMD wrappers for short Windows invocations).
Old shell recipes that combined commands without separators were replaced by
single-line expressions using explicit separators. Repeated lines were removed.
Digits are normalized identically in both references and candidates before
building/querying the 4-gram index. The inference command length limits remain
6–100 characters, preserving the existing runtime budget; the shipped references
use the narrower 10–95 range requested for this collection.

Run `python -m unittest discover -s tests -v` from the repository root to validate
constraints, exact self-matches, indexed/full-scan agreement, and model integrity.
After editing either corpus, retrain that platform with `scripts/train.py` to
publish its new corpus and artifact hashes together. Do not simply refresh a hash
to bypass a reported integrity failure.

Corpus matches indicate lexical resemblance, not proof of malicious intent:
administrative commands can be dual use. The reference corpus is independent of
the supervised train/test split; exact overlaps with held-out examples can affect
reported hybrid detection metrics. A separate external dataset is needed to
measure generalization.
