# CI Gate

A checkpoint is eligible for merge only when:
- `:core-security:test` passes,
- `:app:assembleDebug` passes,
- no fake capability is introduced to satisfy a test,
- build failures are fixed at root cause and re-run.
