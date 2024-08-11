# Security Reviews

---

Quality software cannot be developed in a vacuum. Periodic external audits and code-review help ensure that our software does what we claim and that we do not have any critical vulnerabilities.

## 2022-11-18 - Code audit report
by [Radically Open Security](https://www.radicallyopensecurity.com/)

This was Gosling's first audit of its implementation and specifications.

### Report: [report_ngir-blueprintforfreespeech 1.1.pdf](<pdfs/report_ngir-blueprintforfreespeech 1.1.pdf>)

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
