# Test File with Invisible Characters

This file contains various invisible characters to test the linter.

## Examples

This line has a zero width space:​here (between colon and "here")

This line has a soft hyphen: soft­hyphen (in the word "softhyphen")

This line has a zero width non-joiner: test‌case (between "test" and "case")

This line has a word joiner: word⁠joiner (between "word" and "joiner")

## Normal characters (should not be flagged)

Normal spaces and tabs:	legitimate whitespace
Newlines are also fine

## Mixed content

Some normal text with zero width space:​sneaky
Regular content followed by soft­hyphen issue