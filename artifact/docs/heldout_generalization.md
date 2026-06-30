# Held-Out Generalization

The 48,600 BEP-Scale cases and 4,860 identifier-blind replays are robustness checks over the locked BEP-Deep denominator. They are not the only generalization evidence.

The non-denominator generalization surface is BEP-SpecBench:

- 4,180 source-derived boundary and composite-stress cases;
- fresh `SB_*` case ids that do not overlap the 972 locked fixture ids;
- public source links on every case;
- 29 semantic rules covered;
- label-free declarative oracle coverage over all 4,180 cases.

`artifact/scripts/audit_assessor_objection_closure.py` writes `artifact/results/heldout_generalization_audit.json`, which checks that SpecBench is source linked, non-overlapping with the locked denominator, and covered by the independent declarative oracle.

