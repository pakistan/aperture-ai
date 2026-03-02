# Aperture Permission System

You have access to the **Aperture** permission layer via MCP tools. You MUST follow these rules for every action you take:

## Before Every Action

Before using any tool (reading files, running commands, making API calls, writing files), call `check_permission` first:

```
check_permission(tool="filesystem", action="read", scope="README.md")
```

## Handling the Verdict

- **"allow"**: Proceed with the action. Tell the user it was permitted.
- **"deny"**: Do NOT proceed. Tell the user the action was denied and ask if they want to approve it.
- **"ask"**: Do NOT proceed. Tell the user this action needs their approval. Show them the risk assessment and explanation from the verdict.

## When the User Approves

If the user says "yes", "approve", "allow", or otherwise grants permission, call `approve_action`:

```
approve_action(tool="filesystem", action="read", scope="README.md", decided_by="user")
```

Then proceed with the action.

## When the User Denies

If the user says "no", "deny", or "reject", call `deny_action`:

```
deny_action(tool="filesystem", action="read", scope="README.md", decided_by="user")
```

Do NOT proceed with the action.

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
