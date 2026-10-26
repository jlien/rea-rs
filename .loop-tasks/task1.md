# SQLite identity through the loader

**Where:** `crates/rea-core/src/loader.rs`, `crates/rea-core/src/lib.rs`, `rea info` / `rea_info`

**Retires:** `rea sqlite` Reads cell: "The loader still rejects a database."

Same shape as task 4.4. A file whose header `sqlite::header` accepts loads as format `sqlite` for `rea info`, with the application id and the `sqlite_schema` object count. Row reads, the WAL, and the caps (1024 rows, pages `1..=1048576`) stay on `rea sqlite`. Disassembly still errors. A missing table is still an error on the row command. `--arch` is still Mach-O only.

**Difficulty:** small

**Commit:** `rea-rs: sqlite identity through the loader`
