# Spec notes

Every standards-derived fact the code relies on, with the primary source, section and retrieval
date. Tags:
- **VERIFIED**: read in the primary source on the retrieval date.
- **UNVERIFIED**: not yet read in a primary source. It blocks the milestone named next to it.
- **OPEN**: the source is clear (or contradicts itself), and applying it needs an owner decision
  (see §14).

All retrievals are dated 2026-10-02 unless noted otherwise. Commit SHAs and file hashes are of
the exact files read.

## 1. OpenVEX (output format, M1)

- **Pinned version:** OpenVEX **v0.2.0** (ADR-0002 item 1). VERIFIED.
  - Specification: https://github.com/openvex/spec, `OPENVEX-SPEC.md`. Tag `v0.2.0` (annotated
    tag, 2023-08-22) points to commit `7667061835da09300f913e26be10ee03c05e784d`; the file there
    has SHA-256 `2abdc5d06f2254fea39830e23e482c65d1631e9564a259dd884559a4a21ce330`. `main` at
    `61b5f885d0f481f48683c93345e49ef1a6e9fdff` (2026-09-09) differs from the tag only in link
    style, typos, examples and the `@context` value (below). v0.2.0 is still the latest release.
  - JSON Schema: `openvex_json_schema.json` is **not** in the `v0.2.0` tag (HTTP 404). It was
    added on 2024-03-15 ("feat: json schema for version 0.2.0") and last changed at commit
    `a68ccd19b15a9604d28ef66ebf33f27a772ba4ec` (2025-03-31, "schema: Add missing "type" for
    statements"). SHA-256 `9373597734ed1d3ea5161a8b46d3866c4a8cfe76fd632fdd16aef01fb34b3238`,
    `$schema` draft 2020-12, `$id` `https://github.com/openvex/spec/openvex_json_schema_0.2.0.json`.
- **Document** (schema `required`; spec "Document Struct Fields"): `@context`, `@id`, `author`,
  `timestamp`, `version` (integer >= 1, "must be incremented when any content ... changes") and
  `statements` (array, `minItems` 1, `uniqueItems`). Optional: `role`, `last_updated`, `tooling`.
  `additionalProperties: false`. VERIFIED.
- **`@context`: `https://openvex.dev/ns/v0.2.0`** (OQ-1, owner decision 2026-10-02). The spec at tag `v0.2.0` says it is "Fixed to
  `https://openvex.dev/ns` before 1.0 is released". The spec on `main` says "The URL is structured
  as https://openvex.dev/ns/v[version] ... If the version is omitted, it defaults to v0.0.1", and
  its examples use `https://openvex.dev/ns/v0.2.0`. The schema only requires `format: uri`.
- **Statement** (schema; spec "Statement Fields"): required `vulnerability` and `status`.
  Optional `@id`, `version`, `timestamp`, `last_updated`, `products`, `supplier`,
  `status_notes`, `justification`, `impact_statement`, `action_statement`,
  `action_statement_timestamp`. `additionalProperties: false`. VERIFIED.
  - `status` enum: `not_affected`, `affected`, `fixed`, `under_investigation`.
  - `justification` enum: `component_not_present`, `vulnerable_code_not_present`,
    `vulnerable_code_not_in_execute_path`, `vulnerable_code_cannot_be_controlled_by_adversary`,
    `inline_mitigations_already_exist`.
  - Schema `allOf`: status `not_affected` requires `justification` or `impact_statement`;
    status `affected` requires `action_statement`.
  - Spec status meanings ("Status Labels"): `not_affected` "No remediation is required regarding
    this vulnerability"; `affected` "Actions are recommended to remediate or address this
    vulnerability"; `fixed` "These product versions contain a fix for the vulnerability";
    `under_investigation` "It is not yet known whether these product versions are affected".
  - Spec "Data Inheritance": a complete statement needs products, status, vulnerability and a
    timestamp; timestamps and products may be inherited from the document, but "A document with
    incomplete statements is not valid."
- **Vulnerability:** spec "Vulnerability Data Structure": `name` required ("the main identifier
  used to name the vulnerability"); optional `@id`, `description`, `aliases`. The schema's
  `vulnerability` requires `name` and allows no other keys. fixproof sets `name` to the CVE id.
  VERIFIED.
- **Product / component:** `@id` (IRI) and/or `identifiers` (at least one of `purl`, `cpe22`,
  `cpe23`), optional `hashes`, `subcomponents`. Spec: "the use of Package URLs (purls) is
  recommended". VERIFIED.
- **Format keywords:** the schema uses `format` values `iri`, `uri` and `date-time`. VERIFIED in
  jsonschema 4.26.0, `jsonschema/_format.py` (read from the installed package) and its
  `format-nongpl` extra:
  - `uri` is checked only when `rfc3987` or `rfc3986-validator` is installed; `iri` only with
    `rfc3987` or `rfc3987-syntax`; `date-time` only with `rfc3339-validator`. Without them the
    format checker silently passes all three. None is installed today.
  - `rfc3987` is GPL-3.0-or-later (PyPI metadata); `rfc3986-validator` 0.1.1, `rfc3987-syntax`
    1.1.0 (needs `lark`) and `rfc3339-validator` 0.1.4 (needs `six`) are MIT. They are the
    packages jsonschema's own `format-nongpl` extra names for these formats.
- **Timestamps:** the schema's `format: date-time` is RFC 3339 `date-time`: JSON Schema 2020-12
  Validation §7.3.1, https://json-schema.org/draft/2020-12/json-schema-validation ("Date and
  time format names are derived from RFC 3339, section 5.6"). VERIFIED. UTC with `Z` and whole
  seconds is fixproof's own canonical choice within RFC 3339 (ADR-0005 item 4).
- **Document `@id`:** spec "Public IRI Namespaces": OpenVEX defines the shared namespace
  `https://openvex.dev/docs/[name]`; "Users can start issuing IRIs for their documents by
  appending a IRI valid string" to it. `public` and `example` are reserved names. VERIFIED.
- **How fixproof verdicts map to statuses** (OQ-2, owner decision 2026-10-02): `fixed` ->
  `fixed`; `still_affected` -> `affected` with an `action_statement`; `unknown` ->
  `under_investigation` with the reason in `status_notes`. `not_affected` is never emitted in the
  MVP, including when a fix removed the package.

## 2. CVE JSON 5 record format (CVE ids, M1)

- **Source:** https://github.com/CVEProject/cve-schema, release **v5.2.0** (2025-10-29, the
  latest), commit `5533f6038cc0434e544e69240c704906d591de46`, file
  `schema/CVE_Record_Format.json`, SHA-256
  `33f7517424facfc712c7b808be1b6503fc74b2e6b85979bbaacb9b623ddfde67`, draft-07. VERIFIED.
- **CVE id** (`definitions.cveId`): pattern `^CVE-[0-9]{4}-[0-9]{4,19}$`, "followed by a 4 to 19
  digit number". The current KEV catalogue (§3) contains `CVE-2026-104286`, so ids with more than
  four digits occur in practice. VERIFIED.
- `dataType` enum `CVE_RECORD`; `dataVersion` pattern `^5\.(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*))?$`,
  default `5.2.0`. VERIFIED.
- **Affected versions** (`product.versions[]`, for reference; fixproof takes the fixed version
  from `fix.yaml`, not from the CVE record): each entry is a single `version` + `status`, or a
  range with `versionType` and `lessThan` or `lessThanOrEqual`, plus optional `changes`.
  `status` enum `affected`, `unaffected`, `unknown`. `versionType` is free text (examples
  `custom`, `git`, `maven`, `python`, `rpm`, `semver`). `product.packageURL` "MUST NOT include a
  version". VERIFIED.

## 3. CISA KEV catalogue JSON feed (enrichment, M5)

- **Feed:** https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json.
  Retrieved copy: `catalogVersion` `2026.10.01`, `dateReleased` `2026-10-01T19:54:04.9308Z`,
  `count` 1731, SHA-256 `4e47d6936857ccf0994d2abe1d77d7421bf14e45ff908cc0d8973fe7adc35140`.
  VERIFIED.
- **Schema:** https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json
  (`Last-Modified` 2026-09-16), SHA-256
  `0d5865c98694c5bfba2c78a26caf814f406b3fce8bfb81bef79e99c7f288b0e7`. It declares draft-07 but
  places definitions under `$defs` and references them by JSON pointer. VERIFIED.
  - Catalogue, required: `catalogVersion`, `dateReleased` (date-time), `count`, `vulnerabilities`.
    `title` is present in the feed but not in the schema.
  - Entry, required: `cveID` (pattern `^CVE-[0-9]{4}-[0-9]{4,19}$`), `vendorProject`, `product`,
    `vulnerabilityName`, `dateAdded` (date), `shortDescription`, `requiredAction`, `dueDate`
    (date). Optional: `knownRansomwareCampaignUse` (`Known` or `Unknown`), `forensicTriage`
    (`Yes` or `No`, "per BOD 26-04"), `notes`, `cwes` (pattern `^CWE-([0-9])+$`).
  - `forensicTriage` is recent (BOD 26-04): present on all 1731 entries in the retrieved copy
    (72 `Yes`). Consumers must tolerate fields being added.
- The run records the feed's `catalogVersion`, `dateReleased`, retrieval time and SHA-256 (the
  plan's guardrail). The cache format is decided in M5.

## 4. CycloneDX 1.6 VEX (second output format, M5)

- **Source:** https://github.com/CycloneDX/specification, tag **1.6.2** (release 2026-06-02),
  commit `e833d732337dd33aceb45ff1991f896796f1e5e7`, `schema/bom-1.6.schema.json`, SHA-256
  `18f57f7482593bad9f21b4feed09084640cbeff419d62ad5090c5ceccca5b37d`, draft-07, `$id`
  `http://cyclonedx.org/schema/bom-1.6.schema.json`. Against 1.6.1 it changes only description
  text and the `specVersion` example. Newer: 1.7 (2025-10-21) and 1.7.2 (2026-09-17) (OQ-3).
  VERIFIED.
- `vulnerability.analysis`: `state`, `justification`, `response`, `detail`, `firstIssued`,
  `lastUpdated`. VERIFIED.
  - `state` (`impactAnalysisState`): `resolved`, `resolved_with_pedigree`, `exploitable`,
    `in_triage`, `false_positive`, `not_affected`.
  - `justification` (`impactAnalysisJustification`): `code_not_present`, `code_not_reachable`,
    `requires_configuration`, `requires_dependency`, `requires_environment`,
    `protected_by_compiler`, `protected_at_runtime`, `protected_at_perimeter`,
    `protected_by_mitigating_control`.
  - `response`: `can_not_fix`, `will_not_fix`, `update`, `rollback`, `workaround_available`.
- `vulnerability.affects[]`: required `ref` (a `bom-ref` or BOM-Link); optional `versions[]`,
  each a `version` or a `range` (vers syntax, §5) with `status` (`affectedStatus`: `affected`,
  `unaffected`, `unknown`; default `affected`). VERIFIED.
- The 1.6 schema references external schemas (SPDX licence ids, JSF signatures). Validating
  offline needs them vendored too: UNVERIFIED which files, blocks M5. Which spec versions
  `cyclonedx-python-lib` 11.12.0 writes: UNVERIFIED, blocks M5.

## 5. Package URL (purl) and version ranges (vers) (M1 to M3)

- **purl:** https://github.com/package-url/purl-spec, release **v1.0.1** (2026-08-03), commit
  `b5454e75c29b48e483290689fe635f2517925925`. `PURL-SPECIFICATION.rst` there says the content has
  moved to `docs/` and https://www.packageurl.org/docs/purl/introduction, and points to the
  standard **ECMA-427** (Package-URL Specification 1st Edition). VERIFIED.
  - Type definitions (`types/<type>-definition.json` at v1.0.1). VERIFIED:

    | type | namespace | name | version | qualifiers |
    |---|---|---|---|---|
    | `deb` | required (vendor), case-insensitive | required, case-insensitive | optional | `arch` |
    | `rpm` | required (vendor), case-insensitive | required, case-sensitive | optional (`version-release`) | `epoch`, `arch` |
    | `apk` | required (vendor), case-insensitive | required, case-insensitive | optional | `arch` |
    | `pypi` | prohibited | required, case-insensitive; "Replace underscore _ with dash -" | optional, case-insensitive | `file_name` |
    | `npm` | optional (scope), case-sensitive | required, case-sensitive | optional, case-sensitive | (none) |
    | `maven` | required (groupId), case-sensitive | required (artifactId), case-sensitive | optional, case-sensitive | `classifier`, `type` |
    | `oci` | prohibited | required, case-insensitive | optional, case-insensitive | `arch`, `repository_url`, `tag` |

  - **Case sensitivity default:** `schemas/purl-type-definition.schema-1.0.json` at v1.0.1 (SHA-256
    `b8988773ac628fe97a33fccabaf19bb45262bb4bd56002fa3d0ab3be72dae983`): `case_sensitive`
    "true if this PURL component is case sensitive. If false, the canonical form shall be
    lowercased", default `true`. So a component the table leaves blank (deb, rpm and apk
    versions) is case-sensitive and kept as given. VERIFIED.
  - **Building a canonical purl.** Source: the standard's text in the repository at v1.0.1,
    `docs/specification/standard/specification.md` (SHA-256
    `0d46c09534c787895e75acc719aeea03db09f3ab77fa39220790a6b9f0403fc0`) and
    `docs/specification/how-to-build.md` (SHA-256
    `bafb64309b6507a605e1e69482fb21cb83e938fbe368c1a15258ac867e44b3c9`). The ECMA-427 PDF itself
    was not read. VERIFIED:
    - "Character encoding": component strings are UTF-8, then every octet outside the allowed
      set is percent-encoded per RFC 3986 §2.1. The allowed set is `A-Z`, `a-z`, `0-9` and
      `. - _ ~`. The colon `:` is never encoded, "whether used as a Separator Character or
      otherwise".
    - "Namespace": leading and trailing slashes "are not significant and should be stripped in
      the canonical form"; a decoded segment "shall not be empty". How to build: "Strip the
      **name** from leading and trailing '/'".
    - Namespace segments, name, version and qualifier values are percent-encoded strings; the
      type and qualifier keys are not. Keys are lowercase letters, digits, `.`, `-`, `_` and
      start with a letter; a pair with an empty value is discarded.
    - How to build: lowercase the type; join `key=value` strings and "Sort this list of
      qualifier strings lexicographically", joined with `&`.
  - **Official test vectors:** `tests/types/<type>-test.json` at v1.0.1 (SHA-256: oci
    `a23376cc43bba896555178d7824f5736875038bbdacd77331ae71ca0e3687be4`, deb
    `9a5f89212d6a3c73906fa2576bd15c2bbac83d45439beb3c319a8c7b33e51e0e`, rpm
    `453383f8de2c7e28a8ba3cef6bcdfc1257437151b46225f1db17f9e7d680865b`, apk
    `bdd1b7c1462136ad9f443636cc505e723f333fb3a99c4017458fcee21e700e6f`, pypi
    `da842b6563c74c52a4b3c2001fec370b9e857fdf0abf6c44bf30d2d243dbf07d`, npm
    `8e7d00358125a743e62163e8cc4875e7bfef4339d947a4c5e5cd8a25b3757db4`, maven
    `13ecbb6db32b88969945be148c52a744ad89732386f86945319d55e23a2878c1`). The oci vectors fix the
    canonical image form, for example
    `pkg:oci/debian@sha256:244fd47e07d10?arch=amd64&repository_url=docker.io%2Flibrary%2Fdebian&tag=latest`:
    the digest's `:` stays, `/` in `repository_url` is encoded. (The type definition's own
    examples encode the digest colon as `%3A`; the test vectors and the encoding clause do not.)
  - **Parsing a purl** (M2, to match Syft's packages): `docs/specification/how-to-parse.md` at
    v1.0.1 (SHA-256 `9a8677da3368cd0e39e0f46541f92876946128fc454b5ef7acbb179f30c2010e`): split
    off `#subpath` and `?qualifiers` from the right, then `scheme:`, strip leading `/`, take the
    type up to the first `/`, the version after an `@`, the name after the last `/`, and the
    namespace from the remaining segments, percent-decoding each and applying the type's
    normalisation. VERIFIED. The official vectors add one constraint: an unencoded `@` in an npm
    scope (`pkg:npm/@babel/core`) is part of the namespace, so fixproof takes the version `@`
    only from the last path segment. All 43 success-case `parse` vectors for the seven types
    pass (`tests/test_purl.py`).
  - **`packageurl-python` 0.17.6 against those vectors** (run 2026-10-02): it passes every
    `parse` test for the seven types and every `specification-test.json` case, and fails 16
    `build` and `roundtrip` tests (8 maven, 2 npm, 6 oci), all because it leaves `/` unencoded in
    qualifier values. Its output for an image with a `repository_url` is therefore not canonical
    under v1.0.1.
- **vers:** https://github.com/package-url/vers-spec, release **v1.2.0** (2026-09-09), commit
  `ec1a0c8143b105a054b0f7cb1feb368b85c9c781`, `docs/specification/standard/`. VERIFIED:
  - Clause 5: a vers is `vers:<type>/<constraints>`; constraints separated by an unencoded `|`;
    the type is lowercase ASCII letters, digits, `.` and `-`, starting with a letter.
  - Defined vers types in the repository: `npm` and `pypi` only. `docs/types/vers-types.md`
    lists `deb`, `rpm`, `apk`, `maven` and others with reference URLs but no definition files.
    It notes Debian's `<<` and `>>` "should" be translated to `<` and `>`.
  - §5.3.3.1 comparators: none (equality, the default; a constraint starting with `=` is an
    error), `!=`, `<`, `<=`, `>`, `>=`, and `*` (alone, matches every version). A version
    satisfies the constraints if it is in any of the intervals they define; `|` means neither
    "and" nor "or".
  - §5.3.3.2: `>`, `<`, `=`, `!`, `*`, `|` and `%` inside a version are percent-encoded;
    whitespace other than `%20` is an error.
  - §5.4: constraints are sorted by version, versions are unique; ignoring `!=`, an equality
    constraint "shall be followed only by a constraint with one of: null, '>', or '>='"; after
    removing `!=` and equality constraints the comparators alternate between `>`/`>=` and
    `<`/`<=`.
  - Printable ASCII only: §5.3.3.2 ("A **version** contains only printable ASCII letters, digits
    and punctuation") and `docs/specification/specification.md` (SHA-256
    `dc1c60ab552780b00f825c51b1c4c15d5ba07612d0a1d3c4acc5b6faa387980f`, "A version range specifier
    contains only printable ASCII letters, digits and punctuation"). VERIFIED.
  - **Containment** (needed by M2 and M3, not M1, which checks syntax only):
    `docs/specification/how-to-parse.md` (SHA-256
    `0e479c29f46493386a98a7c734f5eee265aeb1dee846da7e5efdf86fbd07cfae`), "Checking if a version is
    contained within a range". VERIFIED: a lone `*` is IN; a version equal to a constraint
    version with comparator none, `<=` or `>=` is IN; equal to a `!=` version is NOT IN; then,
    over the constraints other than none and `!=`, taken pairwise: below a leading `<`/`<=`
    version is IN, above a trailing `>`/`>=` version is IN, strictly between a `>`/`>=` and the
    next `<`/`<=` is IN, and between a `<`/`<=` and the next `>`/`>=` is NOT IN; anything else
    is NOT IN. Versions compare with the type's own rules; mixing types is an error.
  - **Gap in that algorithm, and how fixproof resolves it:** as written it only examines pairs
    of range constraints, so a range with one bound (for example `vers:pypi/>=2.31.0`) would
    contain no version, against Clause 5.3.3.1's definition (`>=` "includes all versions greater
    than or equal to the provided version"). The reference implementation by the vers authors,
    univers v32.0.1 (`src/univers/version_constraint.py`, SHA-256
    `767af67ed909685ac7f1044546ac2310b6edec61108ce79cab173204d9ce2950`, `contains_version`),
    evaluates a lone constraint, and a lone remaining range constraint, by its comparator.
    fixproof does the same (`versions.contains`). VERIFIED (both texts read 2026-10-02).
  - **Internal conflict, recorded:** Clause 5.3.3.1 (normative text) says a constraint starting
    with `=` is an error, while `specification.md` ("Normalized, canonical representation")
    lists `=` as a comparator and adds `%` to the characters that must be encoded. fixproof
    follows Clause 5 and accepts `%` only as the start of a valid escape.

## 6. Debian version comparison (dpkg, M3)

- **Source:** Debian Policy Manual **v4.7.4.1**, §5.6.12 "Version",
  https://www.debian.org/doc/debian-policy/ch-controlfields.html#version. VERIFIED:
  - Format `[epoch:]upstream_version[-debian_revision]`. The epoch is an unsigned integer,
    zero when omitted. The version is split at the **last** hyphen; no hyphen means no
    debian_revision, which is equivalent to `0`.
  - Compare epoch numerically, then upstream_version, then debian_revision.
  - Each part is compared left to right in alternating runs: first the leading non-digit run,
    compared "lexically" with ASCII values modified so that all letters sort before all
    non-letters and `~` sorts before anything, even the end of a part (sorted example: `~~`,
    `~~a`, `~`, the empty part, `a`); then the leading digit run, compared numerically, where
    an empty run counts as zero. Repeat until a difference or both are exhausted.
  - upstream_version: alphanumerics and `. + - ~`, should start with a digit; hyphens only when a
    debian_revision exists. debian_revision: alphanumerics and `+ . ~`.

## 7. RPM version comparison (M3)

- **Source:** `rpm-version(7)`, https://github.com/rpm-software-management/rpm, tag
  `rpm-6.1.0-release` (2026-08-20, the latest release), commit
  `f41e3668e7aa93bb2da15fc7fe936670adddeac4`, `docs/man/rpm-version.7.scd`, SHA-256
  `dd6ebf07fd2139723681cfded24cf1a348c928324747661257235c912e84d741`. The vers types table
  points to https://rpm-software-management.github.io/rpm/manual/dependencies.html, which now
  redirects to the man pages. VERIFIED:
  - EVR `[EPOCH:]VERSION[-RELEASE]`; omitted epoch is 0; `-` cannot appear inside VERSION or
    RELEASE. "The string consists of ASCII alphanumeric characters, optionally segmented with the
    separators period (.), underscore (_) and the plus sign (+), and operators tilde (~) and caret
    (^)": the permitted set fixproof checks.
  - Components compared left to right, a segment at a time, stopping at the first difference.
    Runs of letters and runs of digits form implicit segments; `.`, `_` and `+` are separators
    and are not compared (`1.0` == `1+0` == `1+.+0`).
  - Numeric segments compare as integers ignoring leading zeros; others lexicographically.
    Numeric segments are newer than alphabetic ones. With all else equal, more segments is newer,
    and an EVR with more components is newer (`0.0` > `0`; `1` < `1.xyz` < `1.0`).
  - `~` sorts a segment older (`1.0` < `2.0~beta1` < `2.0~rc1` < `2.0`); `^` sorts it newer
    but before the next release (`2.0` < `2.0^150825` < `2.0.1`).
  - Known quirks (BUGS section): non-ASCII characters are ignored; `1.f` is newer than `1c.f`.
  - EXAMPLES section: `123` newer than `99`, older than `321`; `1.0.1` newer than `1.0`, older than
    `1.0.2`; `2.60.1-1` newer than `2.0` or `2.60`, older than `3.0`; `1.0-5` newer than `1.0` or
    `1.0-1`, older than `1.0.1`; `5:3.0-1` newer than `6.0-1` or `4:6.0-1`, older than `5:3.1-1`;
    `1.0~beta2` newer than `0.99` and `1.0~beta1`, older than `1.0`; `2.0^20250611` newer than
    `2.0`, older than `2.0.1`; and in "Comparing", `abc123` equals `abc0123`, `abc.123` and
    `abc.000123`.
- **rpm's own code, read as a behavioural reference (GPL; never copied), tag
  `rpm-6.1.0-release`.** VERIFIED 2026-10-02:
  - `rpmio/rpmvercmp.cc` (SHA-256 `52b0bcdd06ad179862f08291cd4e9cd6b37999e2ee07294253a0aa3ac547f8bc`):
    separators are any non-alphanumeric character other than `~` and `^`; `~` sorts before
    everything including the end; `^` sorts after the end of one string but before any segment;
    numeric segments compare ignoring leading zeros, longer wins, then by string; an empty
    segment on the other side means numeric wins; leftover characters win.
  - `rpmio/rpmver.cc` (SHA-256 `bca89ee0bd9568757f77185453bacb8fcdee1b23260c7ab0ec45e6c94a10a44e`):
    `parseEVR` takes the leading digits before `:` as the epoch and everything after the last
    `-` as the release; `rpmverCmp` compares epoch (absent = `0`), version, then release, where a
    missing release ranks below a present one.
  - `tests/rpmvercmp.at` (SHA-256 `55df5ca66658a69b36d251f1ecef151a798baaac47d20a312ac8274718659438`):
    fixproof's `Rpm` comparator agrees with all 91 active vectors. The 12 further lines are
    disabled (`dnl`) in rpm itself: the BUGS cases (implicit segments such as `1b.fc17`, and
    non-ASCII characters, which fixproof rejects as invalid, as `rpmbuild` does).

## 8. Alpine apk version comparison (M3)

- **Source:** vers types table (§5) points to apk-tools `src/version.c`. Read at
  https://gitlab.alpinelinux.org/alpine/apk-tools tag **v3.0.8** (2026-08-31), commit
  `44dcdfc255c26a4e19a4a27f66a54169cce5ca72`, SHA-256
  `5ae40c4b1bb08f2ebb8eb9050088443f9556dff315d6532a773e48cba7d3e75c`. The file is
  **GPL-2.0-only**: it is a behavioural reference, never copied (ADR-0001).
  - Grammar comment: `digit{.digit}...{letter}{_suf{#}}...{~hash}{-r#}`. Suffix order in the
    source: `alpha`, `beta`, `pre`, `rc`, (none), `cvs`, `svn`, `git`, `hg`, `p`. VERIFIED.
  - **Algorithm (v3.0.8), read 2026-10-02.** VERIFIED. A version is an initial digit run, then
    any of: `.` digits; one letter `a`-`z` (only after digits); `_suffix` with an optional
    number (suffix exactly one of `alpha`, `beta`, `pre`, `rc`, `cvs`, `svn`, `git`, `hg`, `p`);
    `~` plus hex digits (a commit hash); `-r` plus digits (the package revision), in that order
    (`apk_version_validate` rejects anything else). Two versions are compared token by token
    while both tokens are of the same kind: digits numerically, except that if either digit
    group after a `.` starts with `0` the two are compared as strings ("similar to Gentoo
    spec"); a letter by its character; a suffix by the order `alpha` < `beta` < `pre` < `rc` <
    (none) < `cvs` < `svn` < `git` < `hg` < `p`; suffix and revision numbers numerically; commit
    hashes as strings. When the kinds differ or one version ends: a version continuing with a
    pre-release suffix (`alpha` to `rc`) is lower; otherwise the token kinds rank, in source
    order, digit < letter < suffix < suffix number < hash < revision < end, and the version
    whose next token ranks higher in that order is the lower one (so `1.0` > `1`, `1.0a` <
    `1.0.1`, `1.0_p1` > `1.0`, `1.0-r1` > `1.0`).
  - **v2 (`v2.14.12`, `src/version.c`, SHA-256
    `88f36759bc84dc5364ec9e69e537c640dea06bf5ed56a1a6ef612e3c23486b4c`) differs:** no `~hash`
    token, and a digit group with leading zeros is encoded as a negative number instead of being
    compared as a string. VERIFIED (source read).
  - **Which Alpine ships which:** aports `main/apk-tools/APKBUILD` `pkgver` per branch
    (gitlab.alpinelinux.org, 2026-10-02): 3.20-stable 2.14.4, 3.21-stable 2.14.6, 3.22-stable
    2.14.12, 3.23-stable and master 3.0.8. VERIFIED.
  - **Dev-time agreement** (not copied: GPL): apk-tools v3.0.8 `test/unit/version.data` (SHA-256
    `daa0a0cd6ec90f42769398e9d01516d3665b61f37046a5dfd9cd7464982542b6`, 788 lines). fixproof's
    `Apk` comparator agrees with 709 comparison and validity lines and disagrees with none; it
    refuses 60 lines that use a leading-zero group or a `~hash` (ADR-0009 item 4); 16 lines use
    apk's fuzzy `~` dependency operator, which fixproof does not need. Checked 2026-10-02.

## 9. Python versions (PEP 440, M3)

- **Source:** PyPA "Version specifiers",
  https://packaging.python.org/en/latest/specifications/version-specifiers/ (approved as PEP 440
  in August 2014; page last updated 2026-09-22; history: May 2025 dev releases are a form of
  pre-release, Nov 2025 arbitrary equality is case-insensitive, Jan 2026 epochs discouraged).
  VERIFIED, section "Summary of permitted suffixes and relative ordering":
  - Epoch numeric, implicit 0. Release segments compare as integer tuples padded with zeros.
  - Within a release: `.devN`, `aN`, `bN`, `rcN`, (none), `.postN`; `c` sorts as `rc`.
  - Within a pre-release: `.devN`, (none), `.postN`. Within a post-release: `.devN`, (none).
- The section's own example ordering ("The following example covers many of the possible
  combinations"): `1.dev0`, `1.0.dev456`, `1.0a1`, `1.0a2.dev456`, `1.0a12.dev456`, `1.0a12`,
  `1.0b1.dev456`, `1.0b2`, `1.0b2.post345.dev456`, `1.0b2.post345`, `1.0rc1.dev456`, `1.0rc1`,
  `1.0`, `1.0+abc.5`, `1.0+abc.7`, `1.0+5`, `1.0.post456.dev34`, `1.0.post456`, `1.0.15`,
  `1.1.dev1`. VERIFIED; `tests/test_versions.py` uses it verbatim.
- Normalisation (same page): "All ascii letters should be interpreted case insensitively within
  a version" (`1.1RC1` is `1.1rc1`); a leading `v` "MUST be ignored for all purposes"; `c` is
  an alternative spelling of `rc`. VERIFIED.
- `packaging` (26.3) implements this; fixproof's tests check it against the list above rather
  than trusting it (ADR-0007 Q2 moved this comparator into M2).

## 10. npm versions (SemVer 2.0.0 and node-semver, M3)

- **SemVer 2.0.0:** https://semver.org/spec/v2.0.0.html; source `semver.md` in
  https://github.com/semver/semver (tag `v2.0.0` = `7c834b3f3a4940d77ab593bc32583004d6a426a9`).
  §11 precedence: compare major, minor, patch numerically; a pre-release has lower precedence than
  the normal version; pre-release identifiers compare dot by dot (numeric numerically, others in
  ASCII order, numeric lower than alphanumeric, a longer set wins when all else is equal); build
  metadata is ignored. VERIFIED.
- **node-semver:** https://github.com/npm/node-semver, tag **v7.8.5** (2026-06-19),
  `README.md` SHA-256 `f1a789dcec285150be24db2ea04dd3175031554fa9834ec92fab83fb5e025a57`,
  section "Prerelease Tags": a range admits a pre-release version only if some comparator in the
  same set has a pre-release on the same `[major, minor, patch]` tuple, unless
  `includePrerelease` is set. VERIFIED. Range grammar (hyphen, X, tilde and caret ranges) is
  not needed: `fix.yaml` states ranges in vers, and the vers `npm` type (vers-spec v1.2.0,
  `types/npm-definition.json`) maps node-semver ranges to vers constraints, with node-semver as
  the version reference. So fixproof needs only SemVer 2.0.0 precedence for npm. VERIFIED.
- **SemVer syntax:** the FAQ "Is there a suggested regular expression (RegEx) to check a SemVer
  string?" is on https://semver.org/spec/v2.0.0.html and in `semver.md` on `master` at commit
  `f99d5485190a47c0863949e7da810a5553e0ed4d` (SHA-256
  `33ebae1a97845991d0b916f3295a88b499e2ec71a6c1fe84c12429077b19ce08`, the copy read), but not in
  the 2013 `v2.0.0` tag, which holds the precedence rules only. It gives the expression for PCRE
  and Python: `^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(...))?(?:\+(...))?$`
  (major, minor, patch, pre-release identifiers, build metadata). fixproof uses it with
  `re.ASCII`, because in Python `\d` would otherwise match non-ASCII digits. §11.4 example:
  `1.0.0-alpha < 1.0.0-alpha.1 < 1.0.0-alpha.beta < 1.0.0-beta < 1.0.0-beta.2 < 1.0.0-beta.11 <
  1.0.0-rc.1 < 1.0.0`; §11.2 example `1.0.0 < 2.0.0 < 2.1.0 < 2.1.1`. VERIFIED.
- **node-semver fixtures** (v7.8.5, ISC): `test/fixtures/comparisons.js` (SHA-256
  `bd632ee8a596cd04fae4752a290322a5e27e0c143356001bde4bc9e66b717509`) and `equality.js`
  (SHA-256 `ffc7ef18180a0f89ace2df1c89893774b22620743271be7fafd72e0ecdb8dac4`). The 19 strict
  comparison pairs and 2 strict equality pairs (no loose-mode option, no leading `v`, `=` or
  space) are vendored as JSON in `tests/fixtures/node-semver/` with the licence. VERIFIED.

## 11. Maven version ordering (M3)

- **Source:** Maven POM reference, "Version Order Specification",
  https://maven.apache.org/pom.html#version-order-specification. VERIFIED:
  - Follows SemVer **1.0.0** precedence for valid lowercase SemVer strings; "not compatible with
    Semantic Versioning 2.0.0" (no special `+` handling). Comparison is case-insensitive.
  - Otherwise: split into tokens at `.`, `-`, `_` and digit/letter transitions (a transition acts
    like `-`); empty tokens become `0`; trailing null values (`0`, `""`, `final`, `ga`) are
    trimmed, repeated at each hyphen from the end; the shorter sequence is padded with nulls
    matching the other side's separator (`0` for `.`, `""` for `-`, `_` or a transition).
  - Qualifier order: `alpha` < `beta` < `milestone` < `rc` = `cr` < `snapshot` < `""` = `final` =
    `ga` = `release` < `sp`; `a`, `b`, `m` abbreviate alpha, beta, milestone when directly
    followed by a number; other qualifiers sort case-insensitively, and alphabetic tokens sort
    before numeric ones.
  - "Trimming Examples": `1.0.0 -> 1`, `1.ga -> 1`, `1.final -> 1`, `1.0 -> 1`, `1. -> 1`,
    `1- -> 1`, `1_ -> 1`, `1.0.0-foo.0.0 -> 1-foo`, `1.0.0-0.0.0 -> 1`. VERIFIED.
  - When the separators differ: `.qualifier = -qualifier < -number < .number`; with the
    abbreviations the qualifier order is `alpha < a1 < beta < b1 < milestone < m1 < rc = cr <
    snapshot < "" = final = ga = release < sp`. VERIFIED.
  - "End Result Examples" (the page's own table): `1 < 1.1`; `1-snapshot < 1 < 1-sp`;
    `1-foo2 < 1-foo10`; `1.foo = 1-foo < 1-1 < 1.1`; `1.ga = 1-ga = 1-0 = 1_0 = 1.0 = 1`;
    `1-sp > 1-ga`; `1-sp.1 > 1-ga.1`; `1-sp-1 < 1-ga-1`; `1-a1 = 1-alpha-1`;
    `1.0-alpha1 = 1.0-ALPHA1`; `1.7 > 1.K`; `5.zebra > 5.aardvark`; `1.α > 1.b`. VERIFIED.
  - "Version Order Testing" says the examples were produced with Maven's own comparator
    (`maven-artifact`). Its test class at tag `maven-3.9.16`,
    `maven-artifact/src/test/java/org/apache/maven/artifact/versioning/ComparableVersionTest.java`
    (SHA-256 `6e180a9c3107261e5e2686c216d6b6bf4a0c8f456902010c504cfb81bcd631ae`, Apache-2.0),
    holds ordered lists (`VERSIONS_QUALIFIER`, `VERSIONS_NUMBER`) and equality and order pairs.
    VERIFIED (file read).
  - **The comparator itself** (Apache-2.0, ported): `maven-artifact/src/main/java/org/apache/maven/
    artifact/versioning/ComparableVersion.java` at `maven-3.9.16` (SHA-256
    `133b7566c3da8f3d1a2feb358d4b10d85073a2c44174d3438e6aa57118b0e1ca`). fixproof's `Maven` class is
    a port; it agrees with every vector in the test class (both ordered lists, 69 equality pairs
    and 31 order pairs, including the expanded MNG-7644 loop), vendored in
    `tests/fixtures/maven/` with Maven's NOTICE. VERIFIED 2026-10-02.
  - **Conflict, recorded:** the POM reference splits tokens at `_` and gives `1_0 = 1`; Maven's
    code at 3.9.16 and at `maven-4.0.0-rc-7` (`compat/maven-artifact/.../ComparableVersion.java`,
    SHA-256 `8465abac8e72eac25e4957d481daa292f89c833f6e9bee7c7616cf17e83e4bcd`) splits only at `.`
    and `-`, so `1_0` ranks above `1` there. All 19 other "End Result Examples" agree with the
    code. fixproof refuses versions containing `_` (`VersionError`, so `unknown`) rather than
    pick a side (ADR-0009 item 6).

## 12. Kubernetes, Syft, Grype and kind (M2, M4)

- **Pod to image mapping:** `k8s.io/api/core/v1/types.go` at Kubernetes **v1.37.1**
  (2026-09-23), `ContainerStatus`. VERIFIED:
  - `image`: "the name of container image that the container is running. The container image
    may not match the image used in the PodSpec, as it may have been resolved by the runtime."
  - `imageID`: "the image ID of the container's image. The image ID may not match the image ID
    of the image used in the PodSpec, as it may have been resolved by the runtime."
  - The API does not promise that `imageID` is a registry manifest digest. VERIFIED in source
    (2026-10-03) for the M4 stack:
    - Kubernetes v1.37.1 kubelet: `pkg/kubelet/kubelet_pods.go` sets `ImageID: cs.ImageRef` ("is
      historically intentional and should not change"); `kuberuntime_container.go` (SHA-256
      `80c123a39a9e9f47c669e802cd6b5f0fd16965e0de2e1c25df5c5f9dcbdd8e3b`) has
      `imageID := status.ImageRef`. So `imageID` is the CRI `ImageRef`. The demo node image runs
      v1.37.0, whose `kuberuntime_container.go` has the same line (read 2026-10-03).
    - containerd v2.3.4 (the version kind v0.33.0's base image builds: `images/base/Dockerfile`
      `ARG CONTAINERD_VERSION="v2.3.4"`), `internal/cri/server/container_status.go` (SHA-256
      `f24834f19abe806be933ea50eb57065526f068e824a2456e1ee445dfda46d653`): `ImageRef` starts as
      the container's platform-specific image reference and is replaced by `repoDigests[0]`
      ("the manifest list digest for multi-arch images") when the image has a repository
      digest; the platform digest is reported separately as `ImageId`.
    - So a pod pulled from a registry reports `registry/repository@sha256:<digest>` (the index
      digest for a multi-platform image), which fixproof can scan; an image with no repository
      digest (for example one side-loaded with `kind load`) does not, and fixproof reports such a
      workload as `unknown`. The M4 demo therefore pulls from a local registry.
  - **Kubernetes Python client** `kubernetes` 36.0.3 (PyPI, Apache-2.0): `V1PodStatus` has
    `container_statuses`, `init_container_statuses`, `ephemeral_container_statuses`;
    `V1ContainerStatus` has `name`, `image`, `image_id`, `state`, `ready`; `V1OwnerReference` has
    `api_version`, `kind`, `name`, `uid`, `controller`; `CoreV1Api.list_namespaced_pod`,
    `AppsV1Api.read_namespaced_replica_set`; `config.new_client_from_config(context=...)`.
    Runtime dependencies it pulls in: certifi, six, python-dateutil, pyyaml, websocket-client,
    requests, requests-oauthlib, urllib3, durationpy, aiohttp (and theirs). VERIFIED (installed
    and inspected 2026-10-03).
  - **kind local registry** (https://kind.sigs.k8s.io/docs/user/local-registry/, 2026-10-03):
    run a `registry` container, create the cluster with containerd's
    `config_path = "/etc/containerd/certs.d"` (not needed from kind v0.27.0; see the v0.33.0
    example below), write
    `/etc/containerd/certs.d/localhost:<port>/hosts.toml` with `[host."http://<registry-name>:5000"]`
    on each node ("localhost in the container is not localhost on the host"), and connect the
    registry to the `kind` network. VERIFIED.
- **RBAC:** https://kubernetes.io/docs/reference/access-authn-authz/rbac/: a `Role`
  (`rbac.authorization.k8s.io/v1`) lists `rules` of `apiGroups`, `resources` and `verbs`; `""`
  is the core group (pods). ReplicaSet is in group `apps`, version `v1`
  (`k8s.io/api/apps/v1/register.go` at v1.37.1). VERIFIED. The Role and RoleBinding shipped in M4
  (`deploy/kubernetes/`; see below).
- **Syft v1.54.0**: tag object `aee4c00c0b0dbdee3d524acdd02f8f20d0c4c2bf`;
  `syft_1.54.0_linux_amd64.tar.gz` SHA-256
  `54a87372498168b2d033e876fd41fa4e8035b872699e525a57046e1f2f09c860` (release checksums file).
  **Grype v0.119.0**: tag object `dd0f59a2ba584e4241b84d9dbb899e8db978c23d`;
  `grype_0.119.0_linux_amd64.tar.gz` SHA-256
  `3fa2dc4b924621ab65404cf08d0b8438d896d80ab949c9d5a4ca283c36004c9b`. VERIFIED.
  Their JSON output, how to read the Grype DB version and build date, and how Grype reports a
  fixed-in version: VERIFIED in M2, see §17.
- **kind v0.33.0**: `kind-linux-amd64` SHA-256
  `aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d`; default node image
  `kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5`
  (release notes). VERIFIED.
- **kubectl v1.37.1** (`https://dl.k8s.io/release/stable.txt` read `v1.37.1` on 2026-10-03):
  `bin/linux/amd64/kubectl` SHA-256
  `65691ff77eb6fa44c908b77a1082c9f092c3b9733b5cefabec0d1104890e21a8`, from the `.sha256` file
  published next to it. VERIFIED.
- **kind local registry, v0.33.0 example** (`site/static/examples/kind-with-registry.sh` at tag
  v0.33.0): "the containerd config patch is not necessary with images from kind v0.27.0+", so
  the demo cluster only writes `hosts.toml` per registry port and connects each registry to the
  `kind` network. VERIFIED (2026-10-03).
- **Applying the RBAC files** (2026-10-03):
  - `kubectl apply -n <ns>` refuses an object whose own `metadata.namespace` differs: "the
    namespace from the provided object %q does not match the namespace %q"
    (`staging/src/k8s.io/cli-runtime/pkg/resource/visitor.go` at v1.37.1, SHA-256
    `6c4caad6296e4e0db489c9bc1ffc7e7f5e72c3847da6955f68abda2347176dc0`). An object with no
    namespace takes the one given. VERIFIED.
  - A RoleBinding subject of kind `ServiceAccount` names the account's namespace (RBAC docs,
    "Referring to subjects": `kind: ServiceAccount`, `name: default`, `namespace: kube-system`),
    so one account in namespace `fixproof` can be bound in every namespace in scope. VERIFIED.
  - Hence two files: `fixproof-reader.yaml` (the namespace and the account, applied once) and
    `fixproof-reader-role.yaml` (Role and RoleBinding with no namespace, applied with `-n` to
    each namespace in scope). See ADR-0010 Amendment 1.
- **More Kubernetes facts the M4 code and files rely on** (read 2026-10-03):
  - Request verbs (`docs/reference/access-authn-authz/authorization.md`, "Determine the request
    verb"): HTTP `GET` is **get** for an individual resource and **list** for a collection. So
    `list_namespaced_pod` needs `list` on `pods` and `read_namespaced_replica_set` needs `get` on
    `replicasets`; the Role grants both verbs on both, as ADR-0010 item 7 accepted. VERIFIED.
  - RoleBinding `roleRef` (`apiGroup: rbac.authorization.k8s.io`, `kind: Role`, `name`) and
    `apiVersion: v1` for Namespace and ServiceAccount: RBAC docs (Role and RoleBinding examples).
    VERIFIED.
  - `automountServiceAccountToken: false` on a ServiceAccount opts out of mounting its token at
    `/var/run/secrets/kubernetes.io/serviceaccount/token`; on a Pod spec it takes precedence
    (`docs/tasks/configure-pod-container/configure-service-account.md`). VERIFIED.
  - `kubectl create token NAME --duration`: "Requested lifetime of the issued token ... The
    server may return a token with a longer or shorter lifetime" (kubectl reference,
    `kubectl_create_token`). VERIFIED.
  - Owner references: `OwnerReference.Controller`, "If true, this reference points to the
    managing controller" (`staging/src/k8s.io/apimachinery/pkg/apis/meta/v1/types.go` at v1.37.0,
    SHA-256 `a544ea7354cf745449e42db03a512f505aea91dc4adcdc79d6e656406066ebc6`); "Only one
    reference can have Controller set to true" (`.../api/validation/objectmeta.go` at v1.37.0,
    SHA-256 `9930a19ca9cdabe68625370624de7a2bc5e9ebea6727b670f5ef8c5a4ee7be80`). A Deployment
    owns its ReplicaSets and a ReplicaSet its pods (`owners-dependents.md`). VERIFIED.
  - Containers and their state (`staging/src/k8s.io/api/core/v1/types.go` at v1.37.0, SHA-256
    `64b70c914fe25eba63bfb325401a551bbd0871e37eb7fd9b9878283a53e6e062`): `PodSpec.InitContainers`
    and `PodSpec.Containers` name every container, so an unscheduled pod (no statuses yet) is
    still listed; `ContainerStateWaiting.Reason` holds a short reason why the container is not yet
    running; `PodPhase` `Pending`. The kubelet's pull-failure reasons are `ImagePullBackOff`
    and `ErrImagePull` (`pkg/kubelet/images/types.go` at v1.37.0). fixproof echoes whatever reason
    the status holds. VERIFIED.
  - Python client 36.0.3 (installed source): `kubernetes.client.exceptions.ApiException` carries
    `status` and `reason` (`exceptions.py`, SHA-256
    `8dff3268325530772431b6f0167e19a398b0d32ce0f41e737ec24b788886a578`);
    `kubernetes.config.ConfigException` for a missing or invalid kubeconfig or context. In
    `config/kube_config.py` (SHA-256
    `d3d764a18c70338bc9364db6664d9960ece21e76d4dd1b5dfe2e138034dc025c`):
    `KUBE_CONFIG_DEFAULT_LOCATION = os.environ.get('KUBECONFIG', '~/.kube/config')` is read once
    at import, and paths are split on `:`; `new_client_from_config` defaults to
    `persist_config=True`, which writes refreshed GCP or OIDC tokens back to the kubeconfig; and
    embedded certificate and key data is written to `tempfile.mkstemp` files that are deleted at
    exit (`atexit`). fixproof passes the path from `KUBECONFIG` at each run and
    `persist_config=False`. VERIFIED.
- **Observed on the demo cluster** (CI run 37110967647, 2026-10-03; kind v0.33.0, node
  v1.37.0, containerd from the node image): all eight pods Running; pods pulled through
  `hosts.toml` from both registries, the password-protected one with a `docker-registry`
  `imagePullSecrets` secret keyed by `localhost:5002`; `imageID` for the certbot pods was exactly
  `docker.io/certbot/certbot@sha256:<the digest in the pod spec>`; the `fixproof-reader` token
  could list pods in `fixproof-demo` and got `403 Forbidden` for `kube-system`; `kubectl auth
  can-i --list` showed `pods` and `replicasets.apps` with `get` and `list` only. OBSERVED.
- **`imageID` names one of the node's names for a digest, not necessarily the pod's registry**
  (CI run 37112442952, 2026-10-03): the same image (one digest) was pushed to both demo
  registries; pod `payments` pulled it as `localhost:5001/…@sha256:83a8…` and pod
  `partner-gateway` as `localhost:5002/…@sha256:83a8…`, and both pods reported `imageID`
  `localhost:5001/…@sha256:83a8…`. In run 37110967647 the order fell the other way. This is the
  containerd rule above (`repoDigests[0]` of the image as stored on the node), seen in practice.
  The digest, and so the content fixproof checks, is the pod's; only the registry name can differ,
  and fixproof reads only through a registry in the allowlist. The demo's password-protected image
  is therefore built with its own digest (`scripts/build_fixtures.py`). OBSERVED.

## 13. Figures in the project plan (not used by code)

- The market and regulatory figures behind the project (Verizon DBIR 2026, KEV remediation rates,
  patch times, EU CRA reporting deadlines) are not encoded anywhere in the MVP; CRA evidence
  export is V2. They are not verified here. Any doc or report text that repeats one must cite
  its primary source first.

## 14. Open questions for the owner

Answered questions keep their text and gain the answer, so the reasoning stays on record.

- **OQ-1 (blocks M1): OpenVEX `@context`.** (a) `https://openvex.dev/ns/v0.2.0`, as the current
  spec text and its examples say; (b) `https://openvex.dev/ns`, as the `v0.2.0` tag says (which
  the current text reads as v0.0.1). Recommended: (a), because it names the version the
  documents are validated against. **Answered 2026-10-02: (a).**
- **OQ-2 (blocks M1): verdict to OpenVEX status.** Proposed: `fixed` -> `fixed`;
  `still_affected` -> `affected` with an `action_statement` (the schema requires one) naming the
  fixed version from `fix.yaml`; `unknown` -> `under_investigation` with the reason in
  `status_notes`. `not_affected` is never emitted in the MVP. The open part: a fix that removes
  the package rather than upgrading it is also `fixed` under the verdict rule. Should that be
  emitted as `not_affected` + `component_not_present` instead, with the stored SBOM and Grype
  outputs as the evidence? Recommended: no for the MVP; always `fixed`, so `not_affected` never
  appears. **Answered 2026-10-02: as proposed, and no `not_affected` in the MVP.**
- **OQ-3 (blocks M5): CycloneDX version.** The plan names 1.6; 1.7.2 is the latest. Recommended:
  stay on 1.6 (patch 1.6.2) unless the library or a buyer needs 1.7. **Answered 2026-10-03: stay
  on 1.6 (patch 1.6.2).**
- **OQ-4 (blocks M3): dpkg comparator and the GPL.** `python-debian` (1.1.1) is
  GPL-2.0-or-later and the project is Apache-2.0. (a) Depend on it, accepting GPL terms for the
  distributed combination; (b) write the §6 algorithm in this project (it is short and fully
  specified) and use `python-debian` only as a dev-only test oracle, never shipped; (c) write it
  with no oracle. Recommended: (b). **Answered 2026-10-02: (b).**
- **OQ-5 (blocks M4 fixtures): the "unreadable" workload.** What makes the sixth workload
  `unknown` in the success test? (a) An image in a registry fixproof has no credentials for;
  (b) an image Syft cannot catalogue (no package database), so the SBOM method fails; (c) a pod
  whose container has no resolved `imageID` (for example ImagePullBackOff). Recommended: (a),
  the most common real case; the others are covered by unit tests. **Answered 2026-10-03: (a).**
- **OQ-6 (blocks M1): range syntax in `fix.yaml`.** (a) A single `fixed_version`, meaning every
  version at or above it is fixed; (b) a vers string (§5); (c) both, (a) required and (b)
  optional for backports. Recommended: (c), because distributions backport fixes to several
  branches, and vers is the standard notation for that. **Answered 2026-10-02: (c).**


## 15. OCI image references (scope.yaml and assets, M1)

- **Digest:** OCI image-spec **v1.1.1** (2025-03-03, the latest), `descriptor.md` §"Digests",
  https://github.com/opencontainers/image-spec/blob/v1.1.1/descriptor.md, SHA-256
  `89399b5ffabfeb9688b66de9afcf08b60691710d94d0f5b061cb30e6fbc75428`. Grammar
  `digest ::= algorithm ":" encoded`; "When the _algorithm identifier_ is `sha256`, the _encoded_
  portion MUST match `/[a-f0-9]{64}/`." VERIFIED.
- **Repository name:** OCI distribution-spec **v1.1.1** (2025-01-29, the latest), `spec.md`,
  SHA-256 `360b29820869bfaac5f73ebfa30669c9172c069ef619f8c6689acc3bcef6f719`, "Workflow
  Categories" > "Pull" > "Pulling manifests": `<name>` "MUST match"
  `[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*(\/[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*)*`. VERIFIED.
- **Full reference with registry host:** the OCI specs do not define it. The de facto grammar is
  `github.com/distribution/reference` **v0.6.0** (commit
  `7b3d8f9323cf25dd4e1a3868cd9be990bfe06308`), `reference.go`, SHA-256
  `39d358c9e2539646ea612a6c9eda1d671b3cd71287873a3cc5fd0ffb2be6c6f3`:
  `reference := name [ ":" tag ] [ "@" digest ]`, `name := [domain '/'] remote-name`,
  `domain := host [':' port-number]`; host is a domain name, IPv4 or bracketed IPv6 address;
  `domain-component := /([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])/`;
  `port-number := /[0-9]+/`. VERIFIED. fixproof's registry pattern is
  `domain-component ('.' domain-component)* [':' port-number]`, so an IPv4 address passes and a
  bracketed IPv6 host does not. Its implicit defaults (a missing domain means Docker Hub, `library/` for single-path
  names) are not applied by fixproof in M1: `scope.yaml` requires the registry host explicitly.
- **Which segment is the registry:** `normalize.go` at the same commit (SHA-256
  `7bad23a44f1bca325c5de6185092b9992c55b7db211fa4f5444b2d80853e7599`), `splitDockerDomain`: the
  first `/`-separated segment is a domain when it equals `localhost`, contains `.` or `:`, or is
  not all lowercase; otherwise the name is on Docker Hub (`docker.io`, with `library/` added to
  single-segment names). VERIFIED. fixproof uses the same test to require an explicit registry
  in `scope.yaml` and rejects references that would fall back to Docker Hub.

## 16. Dependencies, vendored files and other tool behaviour (M1)

- **Runtime packages locked in M1** (`uv.lock`; licences from each release's PyPI metadata,
  retrieved 2026-10-02). VERIFIED:

  | package | locked | licence | why |
  |---|---|---|---|
  | pydantic | 2.13.5 | MIT | data contracts (ADR-0006) |
  | pydantic-core, annotated-types, typing-inspection | 2.46.5, 0.8.0, 0.4.4 | MIT | pulled in by pydantic |
  | typing-extensions | 4.16.0 | PSF-2.0 | pulled in by pydantic |
  | pyyaml | 6.0.3 | MIT | `fix.yaml`, `scope.yaml` (ADR-0006) |
  | jsonschema | 4.26.0 | MIT | VEX validation (ADR-0006) |
  | jsonschema-specifications, referencing, rpds-py, attrs | 2025.9.1, 0.37.0, 2026.6.3, 26.1.0 | MIT | pulled in by jsonschema |
  | rfc3339-validator, rfc3986-validator, rfc3987-syntax | 0.1.4, 0.1.1, 1.1.0 | MIT | `date-time`, `uri`, `iri` checks (§1) |
  | six, lark | 1.17.0, 1.3.1 | MIT | pulled in by rfc3339-validator and rfc3987-syntax |

  Added in M2 (ADR-0007 item 11): `typer` 0.27.2 (MIT) and `packaging` 26.3 (Apache-2.0 OR
  BSD-2-Clause), pulling in `rich` 15.0.0 (MIT), `pygments` 2.21.0 (BSD-2-Clause),
  `markdown-it-py` 4.2.0 and `mdurl` 0.1.2 (MIT, by their PyPI classifiers), `shellingham` 1.5.4
  (ISC) and `annotated-doc` 0.0.5 (MIT).

  Added in M4 (ADR-0010 item 8; PyPI metadata, 2026-10-03): `kubernetes` 36.0.3 (Apache-2.0),
  pulling in `aiohttp` 3.14.3 (Apache-2.0 AND MIT), `aiohappyeyeballs` 2.7.1 (PSF-2.0),
  `aiosignal` 1.4.0, `frozenlist` 1.8.0, `multidict` 6.9.1, `propcache` 0.5.4, `yarl` 1.25.1,
  `requests` 2.34.2, `websocket-client` 1.9.2 (Apache-2.0), `idna` 3.20 and `oauthlib` 4.0.0
  (BSD-3-Clause), `requests-oauthlib` 2.0.0 (ISC), `durationpy` 0.11, `charset-normalizer` 3.5.2
  and `urllib3` 2.8.0 (MIT), `python-dateutil` 2.9.0.post0 (dual Apache-2.0 / BSD-3-Clause), and
  `certifi` 2026.7.22 (MPL-2.0: a file-level copyleft, compatible with use as an unmodified
  dependency). pip-audit reported no known vulnerabilities in the locked tree.

  Dev only: `types-pyyaml` 6.0.12.20260906, Apache-2.0; `python-debian` 1.1.1, GPL-2.0-or-later
  (PyPI metadata, 2026-10-02), the dpkg oracle that is never shipped (OQ-4, ADR-0009 item 2). The per-file hashes are recorded by
  `uv.lock` itself and are not repeated here.
- **Vendored files:** the OpenVEX schema comes from https://github.com/openvex/spec, licence
  CC0-1.0 (GitHub licence API, 2026-10-02). The purl test vectors come from
  https://github.com/package-url/purl-spec, licence MIT; its `LICENSE` at v1.0.1 (SHA-256
  `24fb7204fd3c9396c9d83533448cb988e8e86d6f598d1ab51c6d2e5d7e42bcb1`) is kept next to them in
  `tests/fixtures/purl-spec/`. VERIFIED.
- **Vendored in M3:** `tests/fixtures/node-semver/LICENSE` is node-semver's `LICENSE` at v7.8.5
  (ISC, SHA-256 `4ec3d4c66cd87f5c8d8ad911b10f99bf27cb00cdfcff82621956e379186b016b`);
  `tests/fixtures/maven/NOTICE` is Apache Maven's `NOTICE` at `maven-3.9.16` (SHA-256
  `05ae716d43260f68b3d231d32105c2f837439e03c62440ee9f38703c0406afa1`); the test vectors are in
  §10 and §11. VERIFIED.
- **Generated schemas** declare `$schema` `https://json-schema.org/draft/2020-12/schema`, the
  `$id` of the published JSON Schema 2020-12 meta-schema (fetched 2026-10-02). VERIFIED.
- **YAML numbers:** PyYAML 6.0.3 resolves YAML 1.1 implicit floats (`yaml/resolver.py`, tag
  `tag:yaml.org,2002:float`, pattern `[-+]?(?:[0-9][0-9_]*)\.[0-9_]*...`), so
  `yaml.safe_load("a: 1.10")` gives the float `1.1`. VERIFIED by running it. This is why
  `fix.yaml` versions must be quoted, and why the loader's error message says so.

## 17. Syft and Grype output, the fixture advisory and base images (M2)

- **Syft v1.54.0** (`syft version -o json`, binary checksum-verified per §12): `schemaVersion`
  `16.1.11`. JSON schema `schema/json/schema-16.1.11.json` at tag v1.54.0, SHA-256
  `33837c9da5b76e1331257a2916e0a6f8b936dc42c3ffa6704abf0b292b372188`, `$id`
  `anchore.io/schema/syft/json/16.1.11/document`. VERIFIED:
  - Document requires `artifacts`, `artifactRelationships`, `source`, `distro`, `descriptor`,
    `schema`; `files` is optional.
  - `Descriptor`: `name`, `version` (required), `configuration`. `Schema`: `version`, `url`.
    `Source`: `id`, `name`, `version`, `type`, `metadata` (required), `supplier`. `Location`:
    `path`, `accessPath` (required), `layerID`, `annotations`.
  - `Package` requires `id`, `name`, `version`, `type`, `foundBy`, `locations`, `licenses`,
    `language`, `cpes`, `purl`; optional `metadataType`, `metadata`.
  - `File` has `id`, `location`, `metadata`, `contents`, `digests`, `licenses`, `executable`,
    `unknowns`. `contents` holds file contents when Syft is configured to capture them.
  - Image source metadata (`syft/source/image_metadata.go` at v1.54.0, SHA-256
    `24c180264668ac473a753312432c5d7acb6b04b1954db8b66953b53284db9ba1`): `userInput`, `imageID`,
    `manifestDigest`, `mediaType`, `tags`, `imageSize`, `layers`, `manifest` (raw bytes),
    `config` (raw image config, which includes the image's environment variables), `repoDigests`,
    `architecture`, `os`, `labels`, `annotations`.
  - Observed on 2026-10-02 (`syft dir:` over a `requests` 2.30.0 install): artifact `name`
    `requests`, `version` `2.30.0`, `type` `python`, `purl` `pkg:pypi/requests@2.30.0`, found by
    `python-installed-package-cataloger` from the `dist-info` files; `files` entries carried
    `digests`, `id`, `location`, `metadata` and no `contents`.
- **Grype v0.119.0** (`grype version -o json`): `supportedDbSchema` 6, embeds Syft v1.52.0.
  Output models `grype/presenter/models/*.go` at tag v0.119.0 (SHA-256: `document.go`
  `3bb196c265a964c2bd6f7cbb72aedb8be1b7b054e65df76b0a45662709edbab2`, `match.go`
  `28f1af8ac0146329461510c8c7635c842a52f223de18eebe0033b7049a003e7d`, `vulnerability.go`
  `d288f5bff6649183191dcb758cf4a475e159ae06c82f69b5e5a91a8d074995d5`,
  `vulnerability_metadata.go`
  `cf060d91fffb0039c7f39c5b85db4a44210799c8e811dd843d0086d1c69604d4`, `descriptor.go`
  `3c069fc19886c8964a90645ca8298dadf6a63177d63684fb8911ca00a3e001d1`). VERIFIED:
  - Document: `matches`, `ignoredMatches`, `alertsByPackage`, `source`, `distro`, `descriptor`.
  - Match: `vulnerability`, `relatedVulnerabilities` (list of vulnerability metadata),
    `matchDetails`, `artifact`.
  - Vulnerability metadata: `id`, `dataSource`, `namespace`, `severity`, `urls`, `description`,
    `cvss`, `knownExploited`, `epss`, `cwes`. Vulnerability adds `fix` (`versions`, `state`,
    `available`) and `advisories`.
  - Descriptor: `name`, `version`, `configuration`, `db`, `timestamp`.
  - Package (`package.go`, SHA-256
    `69ab0ebb88ffdc5d7f4457f65b0affac8663f087c1510e0abd5a871164d43005`), the match's `artifact`:
    `id`, `name`, `version`, `type`, `locations`, `language`, `licenses`, `cpes`, `purl`,
    `upstreams`, `metadataType`, `metadata`.
  - `source.target` for an image is Syft's image metadata: observed keys `architecture`,
    `config`, `imageID`, `imageSize`, `layers`, `manifest`, `manifestDigest`, `mediaType`, `os`,
    `repoDigests`, `tags`, `userInput` (`labels` and `annotations` are `omitempty` in
    `image_metadata.go`, so they appear only when set).
- **Grype DB** (`grype db check -o json`, 2026-10-02): candidate `schemaVersion` `v6.1.9`,
  `built` `2026-10-02T06:31:53Z`, archive `vulnerability-db_v6.1.9_2026-10-02T00:35:12Z_1790922713.tar.zst`,
  `checksum` `sha256:3c368df5c3624fe083ad646ca3be59525739dfe9caa4b6d14c7f252d155fbd98`.
  `grype db status -o json` reports `schemaVersion`, `path`, `valid` and `error` when no DB
  exists; once installed: `schemaVersion`, `from` (download URL carrying the checksum), `built`,
  `path`, `valid`. Grype's scan output repeats this under `descriptor.db.status`. The DB takes
  3.0 GB on disk, as `<cache-dir>/6/vulnerability.db`; `grype db update` downloads and installs
  it (3 minutes 16 seconds here). VERIFIED by running it.
- **Observed behaviour, Grype v0.119.0 with that DB (2026-10-02).** VERIFIED by running it:
  - A PyPI match is reported with `vulnerability.id` = the GHSA id and the CVE only in
    `relatedVulnerabilities`: `requests` 2.30.0 gives `GHSA-j8r2-6x86-q33q` (namespace
    `github:language:python`, related `CVE-2023-32681`, `fix.versions` `["2.31.0"]`,
    `fix.state` `fixed`, matcher `python-matcher`). `requests` 2.31.0 has no match for it.
  - Exit code 0 with or without matches (no `--fail-on`); 1 when the DB is missing, and 1 when
    it is older than `db.max-allowed-built-age`.
  - Settings (`grype config`): `check-for-app-update` (default true), `db.auto-update` (true),
    `db.validate-age` (true), `db.max-allowed-built-age` (`120h0m0s`),
    `db.validate-by-hash-on-start` (true), `db.require-update-check` (false); environment form
    `GRYPE_` + upper-case path with `_`.
- **Observed behaviour, Syft v1.54.0 (2026-10-02).** VERIFIED by running it:
  - Settings (`syft config`; environment names from its comments): `check-for-app-update`
    (`SYFT_CHECK_FOR_APP_UPDATE`, default true);
    `file.metadata.selection` (`SYFT_FILE_METADATA_SELECTION`, default `owned-by-package`;
    `none` captures no files);
    `file.content.globs` (default empty, so no file contents). A scan of `registry:2` gave 234
    `files` entries, none with `contents`.
  - Exit code 1 when the image cannot be fetched.
- **Multi-platform index digests** (both tools, `registry:docker.io/library/registry@<index
  digest>`, 2026-10-02). VERIFIED: the tools resolve the index to the host platform (here
  `amd64`/`linux`) and scan that one manifest. `source.metadata.manifestDigest` (Syft) and
  `source.target.manifestDigest` (Grype) are the platform manifest's digest
  (`sha256:46faa9a1...`); the requested index digest appears in `repoDigests` (as
  `index.docker.io/library/registry@sha256:a3d8aaa6...`) and, for Syft, in `source.version`. So
  a verdict covers the scanned platform only.
- **Where the tools find registry credentials:** go-containerregistry v0.22.1
  `pkg/authn/keychain.go` (SHA-256
  `d3ca9c480e184bfd1e697a7e3f5b6f830620b573fdec68be197b83f311709404`), the default keychain: if
  `$HOME/.docker/config.json` or `$DOCKER_CONFIG/config.json` exists, the Docker config is loaded
  from `$DOCKER_CONFIG` (default `~/.docker`); otherwise `$REGISTRY_AUTH_FILE` or Podman's
  `containers/auth.json`; otherwise anonymous. VERIFIED. The integration tests set `DOCKER_CONFIG`
  to an empty directory, so fixproof runs with no credentials, and CI run 36990675252 showed the
  image in the credential-protected registry coming out `unknown`.
- **Image config in tool output:** both tools' JSON carries the raw image config (Syft
  `source.metadata.config`, Grype `source.target.config`) and raw manifest. VERIFIED.
- **Fixture advisory:** CVE-2023-32681 = GHSA-j8r2-6x86-q33q, "Unintended leak of
  Proxy-Authorization header in requests". GitHub Advisory Database (`gh api
  /advisories?cve_id=CVE-2023-32681`, updated 2024-03-27): ecosystem pip, package `requests`,
  vulnerable `>= 2.3.0, < 2.31.0`, first patched `2.31.0`. OSV (`api.osv.dev/v1/vulns/
  GHSA-j8r2-6x86-q33q`, modified 2026-09-10): aliases CVE-2023-32681 and PYSEC-2023-74, PyPI
  `requests`, introduced `2.3.0`, fixed `2.31.0`. The two agree. VERIFIED.
- **Pinned images** (Docker Hub registry API, `HEAD /v2/<repo>/manifests/<tag>`, 2026-10-02):
  `library/python:3.12-slim-bookworm` index
  `sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3`;
  `library/registry:2` index
  `sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373`. Both are OCI image
  indexes (multi-platform). VERIFIED.
- **Plain HTTP for local registries:** go-containerregistry v0.22.1 (the image library under
  Syft's and Grype's registry access), `pkg/name/registry.go` (SHA-256
  `88618463d047e23a991fcc6f3b5304ac0a56fce5a7c5b22660f137d6e89999ef`), `Registry.Scheme()`: `http`
  for `localhost:<port>`, loopback, `*.local` and RFC 1918 addresses, `https` otherwise. VERIFIED
  in the source, and in practice by CI run 36990675252 (2026-10-02), where Syft 1.54.0 and Grype
  0.119.0 read `localhost:5000` and `localhost:5001` over plain HTTP.
- **Syft registry auth settings** (`syft config`, v1.54.0): `registry.auth[]` entries with
  `authority`, `username`, `password`, `token`, `tls-cert` (env `SYFT_REGISTRY_AUTH_*`). This is
  why the stored output never keeps the tool's own `descriptor.configuration`. VERIFIED.
- **Fixture inputs** (2026-10-02). VERIFIED:
  - `requests` wheels, SHA-256 from PyPI's JSON API (`/pypi/requests/<version>/json`):
    2.25.1 `c210084e36a42ae6b9219e00e48287def368a26d03a048ddad7bfee44f75871e`,
    2.30.0 `10e94cc4f3121ee6da529d358cdaeaff2f1c409cd377dbc72b825852f2f7e294`,
    2.31.0 `58cd2187c01e70e6e26505bca751777aa9f2ee0b7f4300988b709f44e013003f`,
    2.32.3 `70761cfe03c773ceb22aa2f671b4757976145175cdfca038c02654d061d6dcc6`.
  - `library/httpd:2.4-alpine` index `sha256:4e585da9d0125dec36d4500a9f5c5df7b2c0a01f67cb47865a91a4b05bdbec1b`
    (Docker Hub registry API), used only for its `htpasswd` in CI.

## 18. Fixture build and CI plumbing (M2)

- **Tool-output fixtures** (`tests/fixtures/tools/*.json`): derived on 2026-10-02 from real runs
  of Syft 1.54.0 and Grype 0.119.0 (DB v6.1.9): `matches` and `artifacts` from `dir:` scans of
  `requests` 2.30.0 and 2.31.0 installs; `source`, `distro` and `descriptor` from the
  `registry:2` image scan (§17). The image identity is synthetic (repository
  `localhost:5001/fixproof/demo-app`, digest = SHA-256 of `fixproof/demo-app`, manifest digest
  `sha256:56272f4e...`), local paths are replaced, `descriptor.configuration` is cut down, and a
  marker (`MARKER=must-not-be-stored`) is planted in the image config and in a file's `contents`
  so tests prove neither is stored. They are test data, not a record of a real image.
- **Docker and local registries:** Docker documentation, `dockerd` reference, "insecure
  registries" (https://docs.docker.com/reference/cli/dockerd/): "Local registries, whose IP
  address falls in the 127.0.0.0/8 range, are automatically marked as insecure as of Docker
  1.3.2. It isn't recommended to rely on this". VERIFIED; CI run 36990675252 pushed to and logged
  in to `localhost:5000` and `localhost:5001` that way (Docker 28.0.4). After a push,
  `docker image inspect` `RepoDigests` held `localhost:5000/fixproof/<name>@sha256:...`, the
  digest the tools then matched. VERIFIED by that run.
- **registry:2 configuration** (https://distribution.github.io/distribution/about/configuration/):
  any setting can be overridden by an environment variable named `REGISTRY_` plus its upper-case
  path (`REGISTRY_STORAGE_FILESYSTEM_ROOTDIRECTORY`), hence `REGISTRY_AUTH=htpasswd`,
  `REGISTRY_AUTH_HTPASSWD_REALM`, `REGISTRY_AUTH_HTPASSWD_PATH` for `auth.htpasswd.realm/path`;
  "The only supported password format is bcrypt" (so `htpasswd -B`). VERIFIED. The registry
  answering `GET /v2/` on port 5000 is observed in the CI run.
- **pip** 26.2.1 (`docs/html/topics/configuration.md`, SHA-256
  `3d66de39ea7fa4bb86e504e9b7dbda5bec8cd4cad86fde7fdcd74ee75ad0fdbd`: environment variables
  `PIP_<UPPER_LONG_NAME>`, so `PIP_DISABLE_PIP_VERSION_CHECK` and `PIP_NO_CACHE_DIR`;
  `docs/html/topics/secure-installs.md`, SHA-256
  `b145105b41ec1a5e01811b4f8c52bde20352ad114d64e9610a512eec1c6924ff`: `--require-hashes` forces
  hash-checking mode; `pip install --help`: `--no-deps` "Don't install package dependencies").
  VERIFIED.
- **GitHub Actions** (docs.github.com, 2026-10-02): the `add-mask` workflow command ("Masking a
  value in a log", the command form of `core.setSecret`); default variable `CI` "Always set to
  true". VERIFIED. Service-container port mapping (`services.<id>.ports`) is shown working by
  run 36990675252.
- **Click usage errors** (the copy vendored in typer 0.27.2, `typer/_click/exceptions.py`):
  `UsageError.exit_code = 2`, which is why `fixproof` maps usage errors to its own exit code 3.
  VERIFIED.

## 19. Live-check ground truth (ADR-0008)

All retrieved 2026-10-02.

- **Certbot pins `requests`:** https://github.com/certbot/certbot, `tools/requirements.txt` at each
  release tag: v2.5.0 and v2.6.0 `requests==2.28.2`; v2.7.0 to v2.10.0 `requests==2.31.0`;
  v2.11.0 `requests==2.32.3`; v5.8.0 `requests==2.34.2`. `tools/pip_install.py` (v2.5.0) installs
  with `PIP_CONSTRAINT` set to `tools/requirements.txt`, and `tools/docker/core/Dockerfile` builds
  the image through it. VERIFIED.
- **Certbot images** (Docker Hub registry API, manifest-list digests): `certbot/certbot:v2.6.0`
  `sha256:92092d214a4eb75d049720d04f7acc50b40ea226d77736bce6a6bf43981b6e86`, `v2.7.0`
  `sha256:68e0f51ce9037d3b022d446772277beb1e9c0fe801e75fbf87db105ab165ad54`, `v5.8.0`
  `sha256:f70ad0adbb7e117f0fe42a63c553f28ea451edabc0148757b6efcd9735acaa20`. VERIFIED.
- **CVE-2023-4911** (glibc, "Looney Tunables"): Debian security tracker,
  https://security-tracker.debian.org/tracker/CVE-2023-4911: source package `glibc` fixed in
  bookworm `2.36-9+deb12u3` and bullseye `2.31-13+deb11u7` (both DSA-5514-1), unstable `2.37-12`;
  buster not affected. CISA KEV (§3 copy): listed, GNU C Library, added 2023-11-21, due
  2023-12-12. VERIFIED.
- **Debian images:** `debian:12.0-slim` `sha256:9bd077d2f77c754f4f7f5ee9e6ded9ff1dff92c6dce877754da21b917c122c77`
  (Grype with the 2026-10-02 DB: distro Debian 12.0, `libc6 2.36-9`, CVE-2023-4911 matched with
  fix `2.36-9+deb12u3`); `python:3.12-slim-bookworm` (§17 digest): distro Debian 12.15, no Debian
  match with an available fix, and Syft lists `libc6` and `libc-bin` `2.36-9+deb12u14`. VERIFIED
  by running Grype and Syft.
- **GitHub scheduled workflows** (docs.github.com, "Events that trigger workflows", `schedule`):
  run only on the default branch; "In a public repository, scheduled workflows are automatically
  disabled when no repository activity has occurred in 60 days"; "Notifications for scheduled
  workflows are sent to the user who last modified the cron syntax"; runs may be delayed at high
  load, especially "the start of every hour". The repository is public. VERIFIED.
- **M3 live cases** (ADR-0009 item 8), retrieved 2026-10-02. VERIFIED:
  - **CVE-2023-5363 on Alpine:** Alpine secdb `https://secdb.alpinelinux.org/v3.18/main.json`
    (SHA-256 `f9cd21cb8d6057f18b0eadd416718dcdba34e80470bb6550a3f89470f98e1372`): `openssl`
    secfix `3.1.4-r0: CVE-2023-5363`. Images: `alpine:3.18.0`
    `sha256:02bb6f428431fbc2809c5d1b41eab5a68350194fb508869a33cb1af4444c9b11` (Grype with the
    2026-10-02 DB: Alpine 3.18.0, `libcrypto3`/`libssl3` `3.1.0-r4`, CVE matched with fix
    `3.1.4-r0`); `alpine:3.22` `sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8`
    (Syft: `libcrypto3`/`libssl3` `3.5.8-r0`).
  - **CVE-2023-0286 on AlmaLinux:** Red Hat Security Data API
    `https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2023-0286.json` (SHA-256
    `708bd2934e87db8281b006bd280359fe77f77dd3bd65af556527aa0e2a2ccf64`): RHEL 9
    `openssl-1:3.0.1-47.el9_1` (RHSA-2023:0946), RHEL 9.0 EUS `openssl-1:3.0.1-46.el9_0`
    (RHSA-2023:1199). Grype matches AlmaLinux 9 against this Red Hat data (namespace
    `redhat:distro:redhat:9`). Images: `almalinux:9.0`
    `sha256:a95a7766fd056b35f72f7b7f7301bcd46e40a6eecd9017e9c41cb4bf22ecb28b` (`openssl-libs`
    `1:3.0.1-43.el9_0`); `almalinux:9` `sha256:3a3fa7f043b142bc8008c8b308d39b47d2c84008addcd52f9f9a7a82d2a90474`
    (Syft: `openssl-libs`/`openssl` `1:3.5.5-6.el9_8`).
    Syft reports RPM versions with the epoch (`1:3.0.1-43.el9_0`) and purls with namespace
    `almalinux` and an `epoch` qualifier.
  - **CVE-2021-44228 (Log4Shell, in CISA KEV since 2021-12-10):** GHSA-jfh8-c2jp-5v3q (GitHub
    Advisory Database): `org.apache.logging.log4j:log4j-core` `>= 2.13.0, < 2.15.0` patched
    `2.15.0`; `>= 2.4, < 2.12.2` patched `2.12.2`; `>= 2.0-beta9, < 2.3.1` patched `2.3.1`.
    Image `ghcr.io/christophetd/log4shell-vulnerable-app`
    `sha256:6f88430688108e512f7405ac3c73d47f5c370780b94182854ea2cddc6bd59929` (single-platform):
    its `build.gradle` uses `spring-boot-starter-log4j2:2.6.1`, and Spring Boot v2.6.1's
    `spring-boot-dependencies/build.gradle` pins `library("Log4j2", "2.14.1")`.
