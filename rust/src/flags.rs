//! The typed view of the flag values `types.rs` shares with the C side.
//!
//! The plain constants of `types.rs` stay the definition of every bit: the
//! generated header carries them and the compile time assertions of the C glue
//! compare nginx' method bits against them.  The types here are what the core
//! uses.  [`WafMode::contains`] is the `mode & flag == flag` of the C
//! implementation, `insert()` and `remove()` are its `|=` and `&= ~`.

use crate::types::*;

bitflags::bitflags! {
    /// One bit of `waf_mode`: a request method or an inspection.
    ///
    /// The method bits are nginx' `NGX_HTTP_xxx` values, `UNKNOWN` is the bit
    /// of a request whose method nginx does not know.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct WafMode: u64 {
        const UNKNOWN = M_UNKNOWN;
        const GET = M_INSPECT_GET;
        const HEAD = M_INSPECT_HEAD;
        const POST = M_INSPECT_POST;
        const PUT = M_INSPECT_PUT;
        const DELETE = M_INSPECT_DELETE;
        const MKCOL = M_INSPECT_MKCOL;
        const COPY = M_INSPECT_COPY;
        const MOVE = M_INSPECT_MOVE;
        const OPTIONS = M_INSPECT_OPTIONS;
        const PROPFIND = M_INSPECT_PROPFIND;
        const PROPPATCH = M_INSPECT_PROPPATCH;
        const LOCK = M_INSPECT_LOCK;
        const UNLOCK = M_INSPECT_UNLOCK;
        const PATCH = M_INSPECT_PATCH;
        const TRACE = M_INSPECT_TRACE;
        const IP = M_INSPECT_IP;
        const URL = M_INSPECT_URL;
        const RBODY = M_INSPECT_RB;
        const ARGS = M_INSPECT_ARGS;
        const UA = M_INSPECT_UA;
        const COOKIE = M_INSPECT_COOKIE;
        const REFERER = M_INSPECT_REFERER;
        /// `waf_mode CMN-METH`.
        const CMN_METH = M_CMN_METH;
        /// `waf_mode ALL-METH`.
        const ALL_METH = M_ALL_METH;
        /// `waf_mode STD`.
        const STD = M_STD;
        /// `waf_mode STATIC`.
        const STATIC = M_STATIC;
        /// `waf_mode DYNAMIC`.
        const DYNAMIC = M_DYNAMIC;
        /// `waf_mode FULL`, every bit including the ones no flag names.
        const FULL = M_FULL;
    }

    /// One bit of `waf_verify_bot_type`: a friendly crawler to verify.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct BotTypes: u32 {
        const GOOGLE = BOT_TYPE_GOOGLE;
        const BING = BOT_TYPE_BING;
        const BAIDU = BOT_TYPE_BAIDU;
        const YANDEX = BOT_TYPE_YANDEX;
        const SOGOU = BOT_TYPE_SOGOU;
        /// Every crawler, the default of `waf_verify_bot on` without a type.
        const ALL =
            BOT_TYPE_GOOGLE | BOT_TYPE_BING | BOT_TYPE_BAIDU | BOT_TYPE_YANDEX | BOT_TYPE_SOGOU;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The typed flags are defined from the constants of the C header, this
    /// freezes the values the glue compiles against.
    #[test]
    fn the_flags_are_the_values_of_the_c_side() {
        assert_eq!(WafMode::UNKNOWN.bits(), M_UNKNOWN);
        assert_eq!(WafMode::GET.bits(), M_INSPECT_GET);
        assert_eq!(WafMode::HEAD.bits(), M_INSPECT_HEAD);
        assert_eq!(WafMode::POST.bits(), M_INSPECT_POST);
        assert_eq!(WafMode::PUT.bits(), M_INSPECT_PUT);
        assert_eq!(WafMode::DELETE.bits(), M_INSPECT_DELETE);
        assert_eq!(WafMode::MKCOL.bits(), M_INSPECT_MKCOL);
        assert_eq!(WafMode::COPY.bits(), M_INSPECT_COPY);
        assert_eq!(WafMode::MOVE.bits(), M_INSPECT_MOVE);
        assert_eq!(WafMode::OPTIONS.bits(), M_INSPECT_OPTIONS);
        assert_eq!(WafMode::PROPFIND.bits(), M_INSPECT_PROPFIND);
        assert_eq!(WafMode::PROPPATCH.bits(), M_INSPECT_PROPPATCH);
        assert_eq!(WafMode::LOCK.bits(), M_INSPECT_LOCK);
        assert_eq!(WafMode::UNLOCK.bits(), M_INSPECT_UNLOCK);
        assert_eq!(WafMode::PATCH.bits(), M_INSPECT_PATCH);
        assert_eq!(WafMode::TRACE.bits(), M_INSPECT_TRACE);
        assert_eq!(WafMode::IP.bits(), M_INSPECT_IP);
        assert_eq!(WafMode::URL.bits(), M_INSPECT_URL);
        assert_eq!(WafMode::RBODY.bits(), M_INSPECT_RB);
        assert_eq!(WafMode::ARGS.bits(), M_INSPECT_ARGS);
        assert_eq!(WafMode::UA.bits(), M_INSPECT_UA);
        assert_eq!(WafMode::COOKIE.bits(), M_INSPECT_COOKIE);
        assert_eq!(WafMode::REFERER.bits(), M_INSPECT_REFERER);
        assert_eq!(WafMode::CMN_METH.bits(), M_CMN_METH);
        assert_eq!(WafMode::ALL_METH.bits(), M_ALL_METH);
        assert_eq!(WafMode::STD.bits(), M_STD);
        assert_eq!(WafMode::STATIC.bits(), M_STATIC);
        assert_eq!(WafMode::DYNAMIC.bits(), M_DYNAMIC);
        assert_eq!(WafMode::FULL.bits(), M_FULL);

        assert_eq!(BotTypes::GOOGLE.bits(), BOT_TYPE_GOOGLE);
        assert_eq!(BotTypes::BING.bits(), BOT_TYPE_BING);
        assert_eq!(BotTypes::BAIDU.bits(), BOT_TYPE_BAIDU);
        assert_eq!(BotTypes::YANDEX.bits(), BOT_TYPE_YANDEX);
        assert_eq!(BotTypes::SOGOU.bits(), BOT_TYPE_SOGOU);
        assert_eq!(
            BotTypes::ALL.bits(),
            BOT_TYPE_GOOGLE | BOT_TYPE_BING | BOT_TYPE_BAIDU | BOT_TYPE_YANDEX | BOT_TYPE_SOGOU
        );
    }

    /// The methods the core replaces by the flags behave like the `|`, `&` and
    /// `&= !` of the C implementation.
    #[test]
    fn the_operations_are_the_raw_bit_maths() {
        // `waf_mode FULL !GET`
        let mut mode = WafMode::FULL;
        mode.remove(WafMode::GET);
        assert_eq!(mode.bits(), M_FULL & !M_INSPECT_GET);
        assert!(!mode.contains(WafMode::GET));
        assert!(mode.contains(WafMode::IP));

        let mut mode = WafMode::empty();
        mode.insert(WafMode::IP);
        mode.insert(WafMode::CMN_METH);
        assert_eq!(mode.bits(), M_INSPECT_IP | M_CMN_METH);

        // `ngx_http_waf_check_flag(waf_mode, INSPECT_URL | r->method)`: every
        // requested bit has to be a bit of the mode.
        for (mode, requested) in [
            (WafMode::GET | WafMode::URL, WafMode::URL | WafMode::GET),
            (WafMode::GET | WafMode::URL, WafMode::URL | WafMode::POST),
            (WafMode::FULL, WafMode::IP | WafMode::TRACE),
        ] {
            assert_eq!(
                mode.contains(requested),
                mode.bits() & requested.bits() == requested.bits()
            );
        }
        assert!(!(WafMode::GET | WafMode::URL).contains(WafMode::URL | WafMode::POST));
    }
}
