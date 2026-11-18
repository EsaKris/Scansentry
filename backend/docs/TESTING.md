# Testing

```
pip install -r requirements/production.txt -r requirements/dev.txt
pytest                                   # SQLite in memory: fast, the default (about 40 s)
TEST_DATABASE_URL=postgresql://user:pass@localhost:5432/scansentry pytest     # real PostgreSQL: run this before releases
```
**Run the suite on PostgreSQL too.** SQLite hides real bugs: it ignores string-length limits, does not enforce row locks (`select_for_update`), and accepts SQL that PostgreSQL rejects.
Running on PostgreSQL during Milestone 9 found three real bugs that SQLite had hidden (a payment-verification lock error that would have caused HTTP 500s, an over-long column in the reward code, and a reward-cap check that was protected only by an accident of unrelated row locking: removing that accident let 12 simultaneous requests all pass a cap of 2). `tests/test_concurrency.py` fires real parallel requests and runs only on PostgreSQL.

Other layers:
- `tests/test_deployment.py`: production settings fail closed, structured logging, Sentry privacy, admin sign-in protection, the smoke script against a live server. It uses a Redis at `REDIS_TEST_URL`
  (default `redis://localhost:6399/0`) for one test and skips it if none is reachable.
- `tests/test_acceptance_map.py`: `docs/ACCEPTANCE.md` must reference only existing tests and list all 23 scenarios.
- Static checks: `bandit -r apps config -ll` (no medium/high findings), `pip-audit -r requirements/production.txt` (no known vulnerabilities), `python manage.py check --deploy --settings=config.settings.production`.
- API contract: `python manage.py spectacular --file openapi.yaml --validate` must stay warning-free and committed.
- `ci/github-actions-backend.yml` runs all of the above (never executed: verify its first run).

**Mutation checking (a habit worth keeping).** After writing tests for a guarantee, deliberately break the guarantee in the code and confirm a test fails. Several real gaps were found this way.
Use read-then-write when scripting mutations (opening a file for writing truncates it before you read it).

**What the suite cannot tell you:** that a real phone reads a printed code, that Google/Paystack behave as their docs say, that the Docker image builds, or that a human attacker cannot find something. See `SANDBOX_TESTING.md`.
