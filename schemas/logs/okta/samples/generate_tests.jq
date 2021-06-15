# Fix timestamp trailing zeros to match Go formatting
def timestamp: sub("0+Z"; "Z");

# Check if value is empty array
def empty_array:   (. | type == "array") and (. | length) == 0;

# Omitempty behavior of Go structs
def omitempty:
    walk(
      if type == "object" then
        with_entries(
           select(  (.value != null) and ( .value | empty_array | not ) )
        )
      else
        .
      end
    );

def sort_keys:
  to_entries
  | sort_by(.key)
  | from_entries;

def indicators:
    map(select(.))
    | unique ;

{
    name: "Okta.Systemlog.Sample \(input_filename) \(input_line_number)",
    logType:"Okta.SystemLog",
    input: .  | sort_keys | @json,
    result:  ( . + {
      p_log_type: "Okta.SystemLog",
      p_event_time: .published | timestamp,
      published: .published | timestamp,
      p_any_domain_names: [.securityContext.domain] | indicators,
      p_any_emails: [.actor.alternateId] | indicators,
      p_any_ip_addresses: ( (.request.ipChain|map(.ip)) + [.client.ipAddress] ) | indicators,
    }) | omitempty | sort_keys | tostring
}
