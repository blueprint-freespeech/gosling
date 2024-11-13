# Security Reviews

---

Quality software cannot be developed in a vacuum. Periodic external audits and code-review help ensure that our software does what we claim and that we do not have any critical vulnerabilities.

## 2024-11-12
by [Radically Open Security](https://www.radicallyopensecurity.com/)

This was Gosling's second audit with a focus on the cgosling-based C/C++, Python, and Java bindings.

### Report: [2024-11-12 - radically-open-security.pdf](<pdfs/2024-11-12 - radically-open-security.pdf>)

### Issues

- [CLN-001 - Java bindings tcp_pump timing oracle](https://github.com/blueprint-freespeech/gosling/issues/125) (High Threat)

    **status**: fixed in [b931e0bfc0a95379b0d7811db2d8d10797c86085](https://github.com/blueprint-freespeech/gosling/commit/b931e0bfc0a95379b0d7811db2d8d10797c86085)

- [CLN-003 - Rsa crate dependency timing side channel](https://github.com/blueprint-freespeech/gosling/issues/127) (Low Threat)

    **status**: rsa crate only enabled with experimmental features, which themselves do not use the broken functionality; remains open until fixed upstream.

- [CLN-012 - Java bindings invalid context](https://github.com/blueprint-freespeech/gosling/issues/126) (High Threat)

    **status**: not a Gosling issue, was a bug in the test

## 2022-11-18
by [Radically Open Security](https://www.radicallyopensecurity.com/)

This was Gosling's first audit of its implementation and specifications.

### Report: [2022-11-18 - radically-open-security.pdf](<pdfs/2022-11-18 - radically-open-security.pdf>)

### Issues

- [GS-001 - DoS through OOM condition](https://github.com/blueprint-freespeech/gosling/issues/45) (Elevated Threat)

    **status**: fixed in [6af83925bac126881bd70550293978c07cdc2fa0](https://github.com/blueprint-freespeech/gosling/commit/6af83925bac126881bd70550293978c07cdc2fa0)

- [GS-002 - DoS through stale connections](https://github.com/blueprint-freespeech/gosling/issues/46) (Moderate Threat)

    **status**: fixed in [8c3dfe34d3683df107271ad677c9fcfc61a9e5dc](https://github.com/blueprint-freespeech/gosling/commit/8c3dfe34d3683df107271ad677c9fcfc61a9e5dc)

- [GS-003 - Protocol is vulnerable to MITM attack](https://github.com/blueprint-freespeech/gosling/issues/47) (Moderate Threat)

    **status**: out of scope, see [discussion](https://github.com/blueprint-freespeech/gosling/issues/47#issuecomment-1328274406)

- [GS-004 - Protocol is not end-to-end encrypted](https://github.com/blueprint-freespeech/gosling/issues/48) (Low Threat)

    **status**: not an issue, see [discussion](https://github.com/blueprint-freespeech/gosling/issues/48#issuecomment-1328280576)

- [GS-005 - DOS through malformed string](https://github.com/blueprint-freespeech/gosling/issues/49) (High Threat)

    **status**: fixed in [fa8f758314a615b739a45fd5ea726f5b55f1b399](https://github.com/blueprint-freespeech/gosling/commit/fa8f758314a615b739a45fd5ea726f5b55f1b399)

- [GS-006 - Path interception vulnerability](https://github.com/blueprint-freespeech/gosling/issues/50) (Low Threat)

    **status**: fixed in [c1ca986496347e31141202edc4984e62116acf31](https://github.com/blueprint-freespeech/gosling/commit/c1ca986496347e31141202edc4984e62116acf31)
