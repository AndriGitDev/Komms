# Komms product brand system

**Name status:** `Komms` is the current project and product name. The project
does not represent it as a registered or legally cleared trademark. Potential
overlap—including `komms.app`—is monitored and documented, but an observed
similar name is not by itself a legal conclusion, automatic rename requirement,
or engineering stop. Under
[stabilization gate P0-02](29-stabilization-program.md), the founder records a
keep, adjust, or rename decision before stable brand and wire identifiers are
frozen, using qualified advice when actual confusion or expansion makes it
proportionate. The product character and accessibility tokens remain reusable
if that decision ever changes.

The application shells use the same visual language as the public Komms site.
The light theme follows `komms.org`; the dark theme follows the technical
`how-it-works` page. This file is the cross-shell contract, not a second brand.

## Product character

- **Light — warm editorial messenger.** Cream canvas, white conversation cards,
  yellow identity moments, coral actions, deep navy anchors.
- **Dark — sovereign technical layer.** Deep navy canvas, teal panels, yellow
  network signals, coral warnings, restrained mono typography for addresses.
- The geometric **K** is the only product mark. Do not substitute the earlier
  radio-wave glyph.
- Conversation content is primary. Folders, labels, addresses, NAT details and
  transport controls are secondary tools.

## Message hierarchy

The front door speaks to ordinary messaging needs before it explains the
network:

1. **Promise:** “Private messaging that keeps working.”
2. **Everyday benefit:** familiar conversations, clear delivery state, easy
   pairing, and recovery a non-specialist can complete.
3. **Reason to believe:** messages are end-to-end encrypted and can use more
   than one supported route.
4. **Advanced proof:** user-owned identity, replaceable infrastructure,
   local/radio/courier fallbacks, published code, a nonprofit public-benefit
   mission, reciprocal source obligations for modified covered software, and
   explicit threat limits.

Do not lead consumer pages with “sovereign,” “DHT,” “relay,” “PQXDH,” “node,”
or transport-selection language. Those are valuable proof for people who want
it, not homework required before sending a message. Do not market fear,
invulnerability, guaranteed delivery, universal anonymity, remote erasure, or
an independent audit that has not happened. The product should win on quality;
privacy and resilience explain why it remains trustworthy.

Use **nonprofit public-benefit mission**, not **registered nonprofit**,
**charity**, or **tax-exempt**, unless a legal entity and jurisdiction-specific
status support that claim. Do not imply that the mission forbids independent
commercial AGPL use.

## Semantic tokens

| Role | Light | Dark |
| --- | --- | --- |
| Background | `#FAFAFA` | `#0F2633` |
| Surface | `#FFFFFF` | `#153746` |
| Raised surface | `#FFF8DC` | `#193F4F` |
| Border | `#E4E1D8` | `#345563` |
| Primary text | `#1A1A1A` | `#FAFAFA` |
| Secondary text | `#6B6B6B` | `#DCE6E8` |
| Brand | `#F2B705` | `#F2B705` |
| Primary action | `#B83431` | `#F2B705` |
| On primary action | `#FFFFFF` | `#1A1A1A` |
| Danger | `#B83431` | `#FF8B82` |
| Success | `#28734B` | `#84D6A5` |

Native accessibility behavior remains mandatory: scalable type, visible focus,
increased-contrast support, reduced motion, and labels that do not rely on color.
Platform system fonts are the fallback; rounded display faces approximate Space
Grotesk, standard UI faces approximate Archivo, and monospaced faces are reserved
for identities and transport details.

## Information hierarchy

1. Conversations, message previews, unread state, and primary compose/pair action.
2. A compact, human-readable node state such as “Node running · 2 LAN peers”.
3. Filters, folders, labels, backup, linked devices, and appearance.
4. Raw addresses, NAT verdicts, listen addresses, relay and queue diagnostics.

Detailed transport information must remain available, but it should never push
the inbox below the first screen.

## Progressive disclosure

The default shell is a messenger, not a node administration dashboard. Keep
pairing, starting a conversation, filtering, and rapid lock within immediate
reach. Move durable administration into a single Settings destination:

1. **Account & devices:** encrypted backup and linked installations.
2. **Privacy & appearance:** always-on protection details and theme.
3. **Conversation organization:** folders, labels, pins, and private icons.
4. **Advanced network & transports:** LAN discovery, bootstrap peers, relays,
   mailbox service, sneakernet, and mesh.

High-threat features must not depend on discovering a special “secure mode.”
Safe protections stay enabled by default; Settings explains their guarantees
and limitations, while advanced transport controls remain available to people
who need them.
