//! The status codes the core answers with when a directive does not override
//! them.  They never cross the ABI: the C glue writes whatever the decision
//! says and knows only nginx' own constants.

pub(crate) const OK: u32 = 200;
pub(crate) const FORBIDDEN: u32 = 403;
pub(crate) const TOO_MANY_REQUESTS: u32 = 429;
pub(crate) const INTERNAL_SERVER_ERROR: u32 = 500;
pub(crate) const SERVICE_UNAVAILABLE: u32 = 503;
