use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Debug)]
pub struct Timestamp(u64);

impl Timestamp {
    pub fn now() -> Self {
        #[cfg(not(target_arch = "wasm32"))]
        {
            Self::from_secs(
                std::time::SystemTime::UNIX_EPOCH
                    .elapsed()
                    .unwrap()
                    .as_secs(),
            )
        }

        #[cfg(target_arch = "wasm32")]
        {
            // In WASM, use js-sys to get the current time
            Self::from_secs((js_sys::Date::now() / 1000.0) as u64)
        }
    }

    pub fn as_secs(&self) -> u64 {
        self.0
    }

    pub(crate) fn from_secs(secs: u64) -> Self {
        Self(secs)
    }
}
