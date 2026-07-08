# async_launched recovery

When a Task call returns `status: "async_launched"` instead of the
subagent's text, the runtime backgrounded it (some runtimes do this
automatically for large parallel batches). Pick one recovery strategy and
apply it consistently across the whole batch:

- **If completion notifications arrive in your conversation:** parse each
  subagent's output block from its notification `result` as it lands. Do not
  end your turn until every subagent is accounted for.
- **If notifications do not arrive:** do NOT poll transcript files. Re-spawn
  the missing subagents in a fresh Task batch with a smaller shard size
  (e.g. 10) and use the synchronous results.
