# signet branding

The signet identity is drawn from the tool itself: a CLI that prints plain,
monochrome text and does nothing decorative. The brand keeps that character —
one ink colour, geometric marks, and type set in the monospace font of
whatever surface renders it (the same way the CLI renders in the user's own
terminal font).

## Marks

| Asset | File | Use |
| --- | --- | --- |
| Monogram | [`monogram.svg`](monogram.svg) | Avatars, favicons, square placements |
| Wordmark | [`wordmark.svg`](wordmark.svg) | README header, documentation, wide placements |

The mark is a signet ring seen face-on: the outer band is the ring, the
hexagon is the engraved seal face, and the knockout centre is the impression
it leaves in wax — a hardware key pressed into a challenge.

## Canonical colours

| Name | Hex | Role |
| --- | --- | --- |
| Ink | `#111111` | The only brand colour: marks, wordmark, headings |
| Paper | `#FFFFFF` | Background; the marks knock out to it |
| Trace | `#6E6E6E` | Secondary text where pure ink is too heavy |

Rules of use:

- Ink on paper (or paper on ink, inverted) only. No gradients, no shadows,
  no third colour.
- The CLI itself stays styling-free: no ANSI colour, no colour library. The
  brand describes the marks around the tool, never the tool's own output.
- Set accompanying type in a monospace stack (`ui-monospace, 'SF Mono',
  Menlo, Consolas, monospace`); the wordmark deliberately inherits the
  viewer's monospace rather than embedding a font.
