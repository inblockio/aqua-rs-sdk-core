# Self-descriptive exports

How `export_tree` makes a tree verifiable by a receiver who does not already
hold its templates.

A typed object names its type by hash only, so a tree of a custom or imported
type is meaningless to a receiver who does not already hold that template.
`export_tree` closes that gap, and does it **by default**: it walks every
typed revision's template plus the full `derives_from` ancestry and embeds
each template revision into a clone of the tree, under its canonical
multihash link.

```rust,ignore
use aqua_rs_sdk_core::{Aquafier, ExportOptions, missing_templates};

// Self-descriptive (the default): verifies with no linked trees.
let portable = aquafier.export_tree(&tree, &[my_template_tree], &ExportOptions::default())?;
assert!(missing_templates(&portable).is_empty());

// Opt out per call site: a plain clone, receiver must resolve the types.
let bare = aquafier.export_tree(&tree, &[], &ExportOptions::bare())?;
```

Template bodies resolve from the tree's own revisions, then the built-in
catalog, then the extra sources you pass (for example trees from a template
import store). The export **fails closed**: if any referenced template or
ancestor cannot be resolved it returns the missing hashes and embeds nothing.
`missing_templates(&tree)` is the same check as a lint, for receivers
triaging an incoming tree or for publishers in CI.

`include_builtin_templates` also defaults to `true`, because **"built-in" is
a property of the receiver, not the sender**. Set it to `false`
(`ExportOptions::non_builtin_only()`) when the receiver is known to share this
crate's catalog and the bytes matter. The cost of the default is template JSON
size per exported tree. Audit templates are never built-in here, so an export
of an audit tree always needs the registry (or fixture) sources and always
embeds the family.

The compat suite proves the round trip end to end: a core-signed T1 audit tree
created with fixture sources and run through `export_tree` verifies in the
**full SDK** with no linked trees. A bare (un-exported) core audit tree
verifies in the full SDK too (the hashes match and the family is still a
full-SDK built-in) and fails in core without sources.

See also [docs/conformance.md](conformance.md) for the compat suite, and
[docs/template-authoring.md](template-authoring.md) section 6 for the
embedding pattern underneath `export_tree`.
