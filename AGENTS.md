# AGENTS.md

Guidance for AI agents working in this repo. It holds documentation and
writing, kept well-organized. The goal is clear, human-sounding writing,
not AI slop.

## Writing
- Plain, direct, specific. Cut filler, hype, and throat-clearing. Start with the point.
- Vary sentence length: mix short, punchy lines with longer ones. Uniform rhythm reads as machine-written.
- Take a position and say it plainly. Don't hedge ("it's important to note," "generally speaking") or trail off into "it depends."
- Use concrete nouns over inflated adjectives: "a framework," not "a robust, comprehensive framework."
- Show with a real example instead of describing in the abstract.
- Go easy on rule-of-three lists. One is fine; a pattern is a tell.
- Never use em-dashes (the `—` character). Rewrite with a comma, colon, period, or parentheses instead.
- Avoid AI-tell words: delve, leverage, robust, seamless, crucial, tapestry, testament, elevate, underscore, boasts, realm, "navigate the landscape."
- Markdown only, one `#` H1 per file. Wrap commands, paths, and code in backticks.

## Organization
- One topic per file. Name files `lowercase-with-hyphens.md`.
- Put new content next to similar content; match the existing folder structure.
- Update the README index when you add or rename a file.
- Link to other docs instead of duplicating them.

## Boundaries
- Never commit secrets, keys, tokens, or private data.
- Only document what is real and verifiable. Never invent facts, sources, or results.
- Don't delete or restructure existing files unless asked.
- Ask before adding new top-level folders or dependencies.

## Commits
- Small, focused commits, one logical change each.
- Present tense, e.g. `add ssh brute-force writeup`.
