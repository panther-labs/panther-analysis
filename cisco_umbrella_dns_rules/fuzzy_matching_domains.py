from difflib import SequenceMatcher

DOMAIN = ''  # The domain to monitor for phishing, for example "google.com"
ALLOW_SET = {
    # List all of your known-good domains here
}
SIMILARITY_RATIO = 0.70


def rule(event):
    # Domains coming through umbrella end with a dot, such as google.com.
    domain = '.'.join(event.get('domain').rstrip('.').split('.')[-2:]).lower()

    return (domain not in ALLOW_SET and
            SequenceMatcher(None, DOMAIN, domain).ratio() >= SIMILARITY_RATIO)


def title(event):
    return 'Suspicious DNS resolution to {}'.format(event.get('domain'))
