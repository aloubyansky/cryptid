# sonar-cryptography Java detection fixtures

The Java files under this directory are copied unmodified from
[sonar-cryptography](https://github.com/cbomkit/sonar-cryptography), tag `1.7.0`
(commit `d1d1b8fad50d65e9f06e380e9f632974f32cb7de`),
directory `java/src/test/files/rules/detection`, excluding its three top-level engine tests
that use test-only rules.

Copyright (C) 2024 PQCA. Licensed under the Apache License, Version 2.0; see `LICENSE.txt`.

`FixtureConformanceTest` compiles them with javac and compares the bytecode engine's findings
with their `// Noncompliant {{...}}` annotations. For javac, it prepares copies with
line-preserving edits only; the files here are never changed.
