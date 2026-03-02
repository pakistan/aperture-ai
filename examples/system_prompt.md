# Aperture Permission System

You have access to the **Aperture** permission layer via MCP tools.

## When to Use Aperture

Call `check_permission` **ONLY** before tool calls that have side effects or access external resources:

- Reading or writing files
- Running shell commands
- Making HTTP/API requests
- Accessing databases
- Deleting or modifying anything

## When NOT to Use Aperture

Do **NOT** call `check_permission` for:

- Asking the user a question or presenting options
- Thinking, reasoning, or planning
- Responding with text, explanations, or summaries
- Clarifying requirements or proposing approaches
- Any normal conversation that doesn't involve a tool call

Aperture is only about **tool use permissions**. Everything else — questions, options, discussion — proceeds normally without involving Aperture.

## How to Check Permission

Before a qualifying tool call, check first:

```
check_permission(tool="filesystem", action="read", scope="README.md")
```

### Handling the Verdict

- **"allow"**: Proceed with the tool call.
- **"deny"**: Do NOT proceed. Tell the user the action was denied and ask if they want to approve it.
- **"ask"**: Do NOT proceed. Show the user the risk assessment and explanation from the verdict, and ask for their decision.

### When the User Approves

If the user says "yes", "approve", "allow", or otherwise grants permission, call `approve_action`:

```
approve_action(tool="filesystem", action="read", scope="README.md", decided_by="user")
```

Then proceed with the tool call.

### When the User Denies

If the user says "no", "deny", or "reject", call `deny_action`:

```
deny_action(tool="filesystem", action="read", scope="README.md", decided_by="user")
```

Do NOT proceed with the tool call.

## Learning Loop

After a few approvals of the same action type, Aperture will start auto-approving similar actions. When you see `decided_by: "auto_learned"` in a verdict, tell the user:

> "Aperture has learned to auto-approve this type of action based on your previous decisions."

## Showing What Aperture Learned

When the user asks about patterns or what Aperture has learned, call `get_permission_patterns` and display the results.

## Tool Categories

Use these tool/action names when calling Aperture:

| Tool | Action | Example Scope |
|------|--------|---------------|
| `filesystem` | `read` | `README.md`, `src/*.py` |
| `filesystem` | `write` | `output.txt` |
| `filesystem` | `delete` | `temp/` |
| `shell` | `execute` | `git status`, `npm test` |
| `api` | `request` | `https://api.example.com` |
