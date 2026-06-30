# Oracle Provenance

BEPGuard separates internal consistency tests from independent oracle evidence.

- The operational evaluator is the main implementation.
- The decision-table oracle is a separate table-driven oracle checked on all 972 locked BEP-Deep fixtures.
- The declarative oracle is a label-free guard-clause implementation over normalized headers, intent class, and request context. It does not import the operational evaluator or the generated static oracle table.
- The generated oracle tests are scoped as release consistency checks over fixture and certificate records. They are not presented as independent correctness evidence.
- Oracle triangulation compares operational, decision-table, and declarative outputs pairwise over all locked fixtures.

The closure audit writes `artifact/results/oracle_provenance_audit.json` and checks the decision-table, declarative, generated-test, and triangulation results together.

