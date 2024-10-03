# panther-analysis Correlation Rule (CR) Style Guide and Best Practices

This style guide highlights essential best practices for writing correlation rules. For a more detailed guide, visit [Correlation Rules](https://docs.panther.com/detections/correlation-rules) in the Panther documentation.

## General advises

- Transition names in rule IDs, and transition IDs should be all caps.
    - e.g. `"GitHub Advanced Security Change NOT FOLLOWED BY repo archived"`
- Boilerplate comments from the CR template in the UI should be removed before committing to PA.
    - e.g. remove `# Create a list of rules to correlate`
- Sequence, Group, and Transition IDs should have meaningful names.
    - e.g. `- ID: GHASChange` instead of `- ID: TR.1`
  - Check for Signal rules that already exist.
    - e.g. we do not want duplicates of `AWS Console Login` rules for every CR that relies on that signal
    - for the guide on Signal rules, please visit [How to create a rule that only produces signals](https://docs.panther.com/detections/correlation-rules/signals#signal-use-cases:~:text=Data%20Explorer.-,How%20to%20create%20a%20rule%20that%20only%20produces%20signals,-To%20create%20a)
- Correlation rules go in `correlation_rules` directory, sub-rules and signals go in the appropriate logtype directory

## Correlation rule fields

### MinMatchCount

`MinMatchCount: 1` is the default value, this can be omitted.

### LookbackWindowMinutes

- `LookbackWindowMinutes: 15` is the default value, but this feels valuable to keep.
- `LookbackWindowMinutes` should be *at least* 1.5x `RateMinutes`.

### WithinTimeFrameMinutes

- `WithinTimeFrameMinutes` is not required and defaults to `LookbackWindowMinutes`.
- Omit `WithinTimeFrameMinutes` in Sequences with only 2 rules

### Match On

- `Match On` fields are not required to be `p_` fields. Especially for CRs where each subrule is for the same LogType, use the regular field instead of the alert context field.
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

You must run `pat validate` against a live Panther instance to test, `pat test` is not sufficient.

### Placing CRs in packs

- If a CR only references 1 LogType it can go in that LogType’s pack
    - If a CR spans multiple LogTypes, put it in the multi-logtype pack
        - Guidance for multi-logtype pack is do not enable the pack, just enable the individual detections you have logs for
    - A pack with CRs should also contain the sub-rules referenced by those CRs
        - AND any globals, data models, etc. that the sub-rules reference
        - can the pack-checker be updated to check for these dependencies?

