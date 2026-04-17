# panther-analysis Correlation Rule Style Guide and Best Practices

This style guide highlights essential best practices for writing correlation rules (CRs). For a more detailed guide, visit [Correlation Rules](https://docs.panther.com/detections/correlation-rules) in the Panther documentation.
This guide provides specialized guidelines on writing CRs, which build upon the general detection writing best practices outlined in [STYLE_GUIDE](https://github.com/panther-labs/panther-analysis/style_guides/STYLE_GUIDE.md)

## General guidelines

- In a rule ID or transition ID, when describing a transition, put that portion of the ID in all-caps
    - e.g. `"GitHub Advanced Security Change NOT FOLLOWED BY repo archived"`
- Boilerplate comments from the CR template in the UI should be removed before committing to PA
    - e.g. remove `# Create a list of rules to correlate`
- Sequence, group, and transition IDs should have meaningful names
    - e.g. `- ID: GHASChange` instead of `- ID: TR.1`
- Check for Signal rules that already exist
    - e.g. we do not want duplicates of `AWS Console Login` rules for every CR that relies on that signal
    - for the guide on Signal rules, please visit [How to create a rule that only produces signals](https://docs.panther.com/detections/correlation-rules/signals#signal-use-cases:~:text=Data%20Explorer.-,How%20to%20create%20a%20rule%20that%20only%20produces%20signals,-To%20create%20a)
- Correlation rules go in `correlation_rules` directory, subrules and signals go in the appropriate logtype directory

## Correlation rule fields

### MinMatchCount

- If you are setting `MinMatchCount` to `1`, you can omit it completely, as `1` is the default value.

### LookbackWindowMinutes

- For ease of understanding, it's valuable to include `LookbackWindowMinutes` even if you are setting it to `15`, which is the default value.
- `LookbackWindowMinutes` should be *at least* 1.5x `RateMinutes`

### WithinTimeFrameMinutes

- `WithinTimeFrameMinutes` is not required and defaults to `LookbackWindowMinutes`
- Omit `WithinTimeFrameMinutes` in sequences with only two rules

### Match On

- `Match On` fields are not required to be `p_` fields. Especially for CRs where each subrule is for the same LogType, use the regular field instead of the alert context field
    - e.g. `- On: repo` instead of `- On: p_alert_context.repo`
- You cannot match on fields that are JSON objects
  - For rules that span multiple LogTypes, where fields must be transformed, add the transformed fields to `p_alert_context`
  - List on list `Match On` criteria works, using an intersection, so if you want to match if RuleA field with RuleB list, map it in alert_context to `[RuleA.value]` , `[RuleB.value1, RuleB.value2]`
- You can match on different field names across multiple rules/transitions, but they all must share the same value.  You cannot match on different values across multiple rules/transitions
    
    ```yaml
    # This is supported
    1: { fieldA: val1 }
    2: { fieldA: val1, fieldB: val1 }
    3: { fieldB: val1}
    ```
    ```yaml
    # This is not supported 
    1: { fieldA: val1 }
    2: { fieldA: val1, fieldB: val2 }
    3: { fieldB: val2 }
    ```

## Before using correlation rules

### Testing

To test your correlation rules before uploading them, run `pat validate` against a live Panther instance. Running `pat test` is not sufficient.

### Placing CRs in packs

- If a CR only references one LogType store it in that LogType’s pack
    - If a CR spans multiple LogTypes, put it in the multi-logtype pack
        - Customers are advised not to enable multi-LogType packs, and to instead enable the individual detections within them that they have log sources set up for
    - A pack with CRs should also contain the subrules referenced by those CRs
        - AND any globals, data models, etc. that the subrules reference
