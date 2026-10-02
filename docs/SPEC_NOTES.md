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
  - §5.4: constraints are sorted by version, versions are unique, and after removing `!=` and
    equality constraints the comparators alternate between `>`/`>=` and `<`/`<=`.
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
    RELEASE.
  - Components compared left to right, a segment at a time, stopping at the first difference.
    Runs of letters and runs of digits form implicit segments; `.`, `_` and `+` are separators
    and are not compared (`1.0` == `1+0` == `1+.+0`).
  - Numeric segments compare as integers ignoring leading zeros; others lexicographically.
    Numeric segments are newer than alphabetic ones. With all else equal, more segments is newer,
    and an EVR with more components is newer (`0.0` > `0`; `1` < `1.xyz` < `1.0`).
  - `~` sorts a segment older (`1.0` < `2.0~beta1` < `2.0~rc1` < `2.0`); `^` sorts it newer
    but before the next release (`2.0` < `2.0^150825` < `2.0.1`).
  - Known quirks (BUGS section): non-ASCII characters are ignored; `1.f` is newer than `1c.f`.

## 8. Alpine apk version comparison (M3)

- **Source:** vers types table (§5) points to apk-tools `src/version.c`. Read at
  https://gitlab.alpinelinux.org/alpine/apk-tools tag **v3.0.8** (2026-08-31), commit
  `44dcdfc255c26a4e19a4a27f66a54169cce5ca72`, SHA-256
  `5ae40c4b1bb08f2ebb8eb9050088443f9556dff315d6532a773e48cba7d3e75c`. The file is
  **GPL-2.0-only**: it is a behavioural reference, never copied (ADR-0001).
  - Grammar comment: `digit{.digit}...{letter}{_suf{#}}...{~hash}{-r#}`. Suffix order in the
    source: `alpha`, `beta`, `pre`, `rc`, (none), `cvs`, `svn`, `git`, `hg`, `p`. VERIFIED.
  - The full comparison algorithm, the v2 (`v2.14.12`) versus v3 differences, and which Alpine
    releases ship which apk-tools: UNVERIFIED, blocks M3.

## 9. Python versions (PEP 440, M3)

- **Source:** PyPA "Version specifiers",
  https://packaging.python.org/en/latest/specifications/version-specifiers/ (approved as PEP 440
  in August 2014; page last updated 2026-09-22; history: May 2025 dev releases are a form of
  pre-release, Nov 2025 arbitrary equality is case-insensitive, Jan 2026 epochs discouraged).
  VERIFIED, section "Summary of permitted suffixes and relative ordering":
  - Epoch numeric, implicit 0. Release segments compare as integer tuples padded with zeros.
  - Within a release: `.devN`, `aN`, `bN`, `rcN`, (none), `.postN`; `c` sorts as `rc`.
  - Within a pre-release: `.devN`, (none), `.postN`. Within a post-release: `.devN`, (none).
- `packaging` (26.3 on PyPI) implements this; the M3 table tests it rather than trusting it.

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
  `includePrerelease` is set. VERIFIED. Full range grammar (hyphen, X, tilde and caret ranges):
  UNVERIFIED, blocks M3.

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
  - The rules when the separators differ, and the "Version Order Testing" examples: UNVERIFIED,
    block M3.

## 12. Kubernetes, Syft, Grype and kind (M2, M4)

- **Pod to image mapping:** `k8s.io/api/core/v1/types.go` at Kubernetes **v1.37.1**
  (2026-09-23), `ContainerStatus`. VERIFIED:
  - `image`: "the name of container image that the container is running. The container image
    may not match the image used in the PodSpec, as it may have been resolved by the runtime."
  - `imageID`: "the image ID of the container's image. The image ID may not match the image ID
    of the image used in the PodSpec, as it may have been resolved by the runtime."
  - The API does not promise that `imageID` is a registry manifest digest. Its format under
    containerd, and for images side-loaded into kind (`kind load`), which may have no registry
    digest: UNVERIFIED, blocks M4.
- **RBAC:** https://kubernetes.io/docs/reference/access-authn-authz/rbac/: a `Role`
  (`rbac.authorization.k8s.io/v1`) lists `rules` of `apiGroups`, `resources` and `verbs`; `""`
  is the core group (pods). ReplicaSet is in group `apps`, version `v1`
  (`k8s.io/api/apps/v1/register.go` at v1.37.1). VERIFIED. The exact Role and RoleBinding ship
  in M4.
- **Syft v1.54.0**: tag object `aee4c00c0b0dbdee3d524acdd02f8f20d0c4c2bf`;
  `syft_1.54.0_linux_amd64.tar.gz` SHA-256
  `54a87372498168b2d033e876fd41fa4e8035b872699e525a57046e1f2f09c860` (release checksums file).
  **Grype v0.119.0**: tag object `dd0f59a2ba584e4241b84d9dbb899e8db978c23d`;
  `grype_0.119.0_linux_amd64.tar.gz` SHA-256
  `3fa2dc4b924621ab65404cf08d0b8438d896d80ab949c9d5a4ca283c36004c9b`. VERIFIED.
  Their JSON output schemas, how to read the Grype DB version and build date, and how Grype
  reports a fixed-in version: UNVERIFIED, block M2.
- **kind v0.33.0**: `kind-linux-amd64` SHA-256
  `aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d`; default node image
  `kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5`
  (release notes). VERIFIED.

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
  stay on 1.6 (patch 1.6.2) unless the library or a buyer needs 1.7.
- **OQ-4 (blocks M3): dpkg comparator and the GPL.** `python-debian` (1.1.1) is
  GPL-2.0-or-later and the project is Apache-2.0. (a) Depend on it, accepting GPL terms for the
  distributed combination; (b) write the §6 algorithm in this project (it is short and fully
  specified) and use `python-debian` only as a dev-only test oracle, never shipped; (c) write it
  with no oracle. Recommended: (b).
- **OQ-5 (blocks M4 fixtures): the "unreadable" workload.** What makes the sixth workload
  `unknown` in the success test? (a) An image in a registry fixproof has no credentials for;
  (b) an image Syft cannot catalogue (no package database), so the SBOM method fails; (c) a pod
  whose container has no resolved `imageID` (for example ImagePullBackOff). Recommended: (a),
  the most common real case; the others are covered by unit tests.
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

  Dev only: `types-pyyaml` 6.0.12.20260906, Apache-2.0. The per-file hashes are recorded by
  `uv.lock` itself and are not repeated here.
- **Vendored files:** the OpenVEX schema comes from https://github.com/openvex/spec, licence
  CC0-1.0 (GitHub licence API, 2026-10-02). The purl test vectors come from
  https://github.com/package-url/purl-spec, licence MIT; its `LICENSE` at v1.0.1 (SHA-256
  `24fb7204fd3c9396c9d83533448cb988e8e86d6f598d1ab51c6d2e5d7e42bcb1`) is kept next to them in
  `tests/fixtures/purl-spec/`. VERIFIED.
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
- **Grype DB** (`grype db check -o json`, 2026-10-02): candidate `schemaVersion` `v6.1.9`,
  `built` `2026-10-02T06:31:53Z`, archive `vulnerability-db_v6.1.9_2026-10-02T00:35:12Z_1790922713.tar.zst`,
  `checksum` `sha256:3c368df5c3624fe083ad646ca3be59525739dfe9caa4b6d14c7f252d155fbd98`.
  `grype db status -o json` reports `schemaVersion`, `path`, `valid` and `error` when no DB
  exists; once installed: `schemaVersion`, `from` (download URL carrying the checksum), `built`,
  `path`, `valid`. Grype's scan output repeats this under `descriptor.db.status`. The DB takes
  3.0 GB on disk. VERIFIED.
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
  - Settings (`syft config`): `check-for-app-update` (default true);
    `file.metadata.selection` (default `owned-by-package`; `none` captures no files);
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
