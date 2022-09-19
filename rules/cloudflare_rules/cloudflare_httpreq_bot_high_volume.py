def rule(event):
    # Bot scores are [1, 99] where scores < 30 indicating likely automated
    # https://developers.cloudflare.com/bots/concepts/bot-score/
    if event.get("BotScore", 100) >= 30:
        return False
    return True
