//! The typed view of `waf_mode` and `waf_verify_bot_type`.
//!
//! The bits are defined here, they are an implementation detail of the core
//! and never cross the ABI.  [`WafMode::contains`] means `mode & flag == flag`,
//! `insert()` and `remove()` are `|=` and `&= ~`.

use crate::abi::NgxWafMethod;

bitflags::bitflags! {
    /// One bit of `waf_mode`: a request method or an inspection.
    ///
    /// The method bits are the `NGX_HTTP_xxx` values of nginx; the glue maps
    /// the method of the request onto [`NgxWafMethod`] and
    /// [`WafMode::for_method`] turns it into one of them.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct WafMode: u64 {
        /// The method nginx does not know.
        const UNKNOWN = 0x0001;
        const GET = 0x0002;
        const HEAD = 0x0004;
        const POST = 0x0008;
        const PUT = 0x0010;
        const DELETE = 0x0020;
        const MKCOL = 0x0040;
        const COPY = 0x0080;
        const MOVE = 0x0100;
        const OPTIONS = 0x0200;
        const PROPFIND = 0x0400;
        const PROPPATCH = 0x0800;
        const LOCK = 0x1000;
        const UNLOCK = 0x2000;
        const PATCH = 0x4000;
        const TRACE = 0x8000;
        const IP = 0x10000;
        const URL = 0x20000;
        const RBODY = 0x40000;
        const ARGS = 0x80000;
        const UA = 0x100000;
        const COOKIE = 0x200000;
        const REFERER = 0x400000;
        /// `waf_mode CMN-METH`.
        const CMN_METH = Self::GET.bits() | Self::POST.bits() | Self::HEAD.bits();
        /// `waf_mode ALL-METH`.
        const ALL_METH = Self::GET.bits()
            | Self::HEAD.bits()
            | Self::POST.bits()
            | Self::PUT.bits()
            | Self::DELETE.bits()
            | Self::MKCOL.bits()
            | Self::COPY.bits()
            | Self::MOVE.bits()
            | Self::OPTIONS.bits()
            | Self::PROPFIND.bits()
            | Self::PROPPATCH.bits()
            | Self::LOCK.bits()
            | Self::UNLOCK.bits()
            | Self::PATCH.bits()
            | Self::TRACE.bits();
        /// `waf_mode STD`.
        const STD = Self::IP.bits()
            | Self::URL.bits()
            | Self::RBODY.bits()
            | Self::ARGS.bits()
            | Self::UA.bits()
            | Self::CMN_METH.bits();
        /// `waf_mode STATIC`.
        const STATIC = Self::IP.bits()
            | Self::URL.bits()
            | Self::UA.bits()
            | Self::GET.bits()
            | Self::HEAD.bits();
        /// `waf_mode DYNAMIC`.
        const DYNAMIC = Self::IP.bits()
            | Self::URL.bits()
            | Self::RBODY.bits()
            | Self::ARGS.bits()
            | Self::UA.bits()
            | Self::COOKIE.bits()
            | Self::CMN_METH.bits();
        /// `waf_mode FULL`, every bit including the ones no flag names.
        const FULL = u64::MAX;
    }

    /// One bit of `waf_verify_bot_type`: a friendly crawler to verify.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct BotTypes: u32 {
        const GOOGLE = 0x01;
        const BING = 0x02;
        const BAIDU = 0x04;
        const SOGOU = 0x08;
        const YANDEX = 0x10;
        /// Every crawler, the default of `waf_verify_bot on` without a type.
        const ALL = Self::GOOGLE.bits()
            | Self::BING.bits()
            | Self::BAIDU.bits()
            | Self::YANDEX.bits()
            | Self::SOGOU.bits();
    }
}

impl WafMode {
    /// The `waf_mode` bit of one request method.  The glue maps the bits of
    /// nginx onto [`NgxWafMethod`], the core owns the mapping onto its own
    /// flag word.
    pub(crate) fn for_method(method: NgxWafMethod) -> WafMode {
        match method {
            NgxWafMethod::Unknown => WafMode::UNKNOWN,
            NgxWafMethod::Get => WafMode::GET,
            NgxWafMethod::Head => WafMode::HEAD,
            NgxWafMethod::Post => WafMode::POST,
            NgxWafMethod::Put => WafMode::PUT,
            NgxWafMethod::Delete => WafMode::DELETE,
            NgxWafMethod::Mkcol => WafMode::MKCOL,
            NgxWafMethod::Copy => WafMode::COPY,
            NgxWafMethod::Move => WafMode::MOVE,
            NgxWafMethod::Options => WafMode::OPTIONS,
            NgxWafMethod::Propfind => WafMode::PROPFIND,
            NgxWafMethod::Proppatch => WafMode::PROPPATCH,
            NgxWafMethod::Lock => WafMode::LOCK,
            NgxWafMethod::Unlock => WafMode::UNLOCK,
            NgxWafMethod::Patch => WafMode::PATCH,
            NgxWafMethod::Trace => WafMode::TRACE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bit layout is frozen here so a reordering is a visible change.
    #[test]
    fn the_flag_layout_is_stable() {
        assert_eq!(WafMode::UNKNOWN.bits(), 0x0001);
        assert_eq!(WafMode::GET.bits(), 0x0002);
        assert_eq!(WafMode::HEAD.bits(), 0x0004);
        assert_eq!(WafMode::POST.bits(), 0x0008);
        assert_eq!(WafMode::PUT.bits(), 0x0010);
        assert_eq!(WafMode::DELETE.bits(), 0x0020);
        assert_eq!(WafMode::MKCOL.bits(), 0x0040);
        assert_eq!(WafMode::COPY.bits(), 0x0080);
        assert_eq!(WafMode::MOVE.bits(), 0x0100);
        assert_eq!(WafMode::OPTIONS.bits(), 0x0200);
        assert_eq!(WafMode::PROPFIND.bits(), 0x0400);
        assert_eq!(WafMode::PROPPATCH.bits(), 0x0800);
        assert_eq!(WafMode::LOCK.bits(), 0x1000);
        assert_eq!(WafMode::UNLOCK.bits(), 0x2000);
        assert_eq!(WafMode::PATCH.bits(), 0x4000);
        assert_eq!(WafMode::TRACE.bits(), 0x8000);
        assert_eq!(WafMode::IP.bits(), 0x10000);
        assert_eq!(WafMode::URL.bits(), 0x20000);
        assert_eq!(WafMode::RBODY.bits(), 0x40000);
        assert_eq!(WafMode::ARGS.bits(), 0x80000);
        assert_eq!(WafMode::UA.bits(), 0x100000);
        assert_eq!(WafMode::COOKIE.bits(), 0x200000);
        assert_eq!(WafMode::REFERER.bits(), 0x400000);
        assert_eq!(
            WafMode::CMN_METH.bits(),
            WafMode::GET.bits() | WafMode::POST.bits() | WafMode::HEAD.bits()
        );
        // Every method bit, the unknown method is not one of them.
        assert_eq!(WafMode::ALL_METH.bits(), 0xfffe);
        assert_eq!(WafMode::FULL.bits(), u64::MAX);

        assert_eq!(
            BotTypes::ALL.bits(),
            BotTypes::GOOGLE.bits()
                | BotTypes::BING.bits()
                | BotTypes::BAIDU.bits()
                | BotTypes::YANDEX.bits()
                | BotTypes::SOGOU.bits()
        );
    }

    /// Every known method names one bit, and the unknown method its own.
    #[test]
    fn every_method_has_its_bit() {
        for (method, expected) in [
            (NgxWafMethod::Unknown, WafMode::UNKNOWN),
            (NgxWafMethod::Get, WafMode::GET),
            (NgxWafMethod::Head, WafMode::HEAD),
            (NgxWafMethod::Post, WafMode::POST),
            (NgxWafMethod::Put, WafMode::PUT),
            (NgxWafMethod::Delete, WafMode::DELETE),
            (NgxWafMethod::Mkcol, WafMode::MKCOL),
            (NgxWafMethod::Copy, WafMode::COPY),
            (NgxWafMethod::Move, WafMode::MOVE),
            (NgxWafMethod::Options, WafMode::OPTIONS),
            (NgxWafMethod::Propfind, WafMode::PROPFIND),
            (NgxWafMethod::Proppatch, WafMode::PROPPATCH),
            (NgxWafMethod::Lock, WafMode::LOCK),
            (NgxWafMethod::Unlock, WafMode::UNLOCK),
            (NgxWafMethod::Patch, WafMode::PATCH),
            (NgxWafMethod::Trace, WafMode::TRACE),
        ] {
            assert_eq!(WafMode::for_method(method), expected);
        }
    }

    /// The bit operations behave like the raw `|`, `&` and `&= !` arithmetic.
    #[test]
    fn the_operations_are_the_raw_bit_maths() {
        // `waf_mode FULL !GET`
        let mut mode = WafMode::FULL;
        mode.remove(WafMode::GET);
        assert_eq!(mode.bits(), !WafMode::GET.bits());
        assert!(!mode.contains(WafMode::GET));
        assert!(mode.contains(WafMode::IP));

        let mut mode = WafMode::empty();
        mode.insert(WafMode::IP);
        mode.insert(WafMode::CMN_METH);
        assert_eq!(mode.bits(), WafMode::IP.bits() | WafMode::CMN_METH.bits());

        // Every requested bit has to be a bit of the mode.
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
