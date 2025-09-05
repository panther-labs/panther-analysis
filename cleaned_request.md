You are an expert LLM/ML engineer. Our goal is to pre-seed critical schema knowledge into the system prompt of a triage/investigation agent as a "cheat sheet" for common, high-value data sources.

```xml
<common_panther_schemas>
<panther_audit>
For user authentication and audit events, the primary table is 'panther_logs.public.panther_audit'.
Key columns for authentication analysis include:
- p_event_time (timestamp): The UTC time of the event.
- actionName (string): The type of action (e.g., 'SIGN_IN').
- actionResult (string): The outcome (e.g., 'SUCCEEDED', 'FAILED').
- actor (object): Contains user details like 'actor:name', 'actor:email'.
- sourceIP (string): The source IP address of the request.
</panther_audit>
</common_panther_schemas>
```

By providing this context upfront, the expert agent can live up to its name. It can skip the discovery steps for common tasks and immediately construct a precise query, drastically improving efficiency.

Please review the query history for the last month and build a set of common panther schemas for us to inject into the system prompt. Use the additional table/schema tools to augment if needed.
