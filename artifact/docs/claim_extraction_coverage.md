# Claim Extraction Coverage

The artifact intentionally claims a conservative admitted-source denominator. It does not claim recall over every browser-policy sentence in upstream specifications, public documentation, or framework guides.

The release denominator contains:

- 45 admitted source-grounded claims;
- 35 encoded semantic/protocol rules;
- 15 public source records;
- multiple policy families, including CSP, CORS, HSTS, COEP/CORP/CORS, COOP/COEP/Permissions-Policy, and framework-specific policy surfaces.

Claims outside the admitted denominator are not counted as failures or successes. This prevents the artifact from implying broad ecosystem coverage that it does not measure. The claim-scope audit writes `artifact/results/claim_extraction_coverage_audit.json`.

