# Rust quick start

The same genesis → sign → verify flow as the README's TypeScript example,
using the crate directly. Add the dependencies from the README's
[Install](../README.md#install) section first.

```rust,no_run
use aqua_rs_sdk_core::schema::{AquaTreeWrapper, FileData, SigningCredentials};
use aqua_rs_sdk_core::{generate_ed25519, Aquafier};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let aquafier = Aquafier::new();

    // 1. Create a genesis revision for some content.
    let file = FileData::new(
        "hello.txt".to_string(),
        b"hello world".to_vec(),
        PathBuf::from("hello.txt"),
    );
    let tree = aquafier.create_genesis_revision(file.clone(), None)?;

    // 2. Sign it with a fresh Ed25519 key (did:key identity).
    let (secret, _did) = generate_ed25519();
    let creds = SigningCredentials::Did { did_key: secret.to_vec() };
    let signed = aquafier
        .sign_aqua_tree(AquaTreeWrapper::new(tree, None, None), &creds, None, None)
        .await?;

    // 3. Verify the full pipeline (structure, hashes, schema, signature).
    let result = aquafier
        .verify_aqua_tree(
            AquaTreeWrapper::new(signed.aqua_tree, Some(file.clone()), None),
            vec![file],
        )
        .await?;
    assert!(result.is_verified());
    Ok(())
}
```

Typed objects work the same way: retrieve the template, provide a payload that
matches its JSON Schema, and the SDK builds the tree. See
[template-api.md](template-api.md) for the template helper APIs, the
validated-creation path, and a registry-sourced example.
