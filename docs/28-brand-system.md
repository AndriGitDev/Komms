# Komms product brand system

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
