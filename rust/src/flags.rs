//! The typed view of `waf_verify_bot_type`.

bitflags::bitflags! {
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
            | Self::SOGOU.bits()
            | Self::YANDEX.bits();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_bot_has_its_bit() {
        assert_eq!(
            BotTypes::ALL.bits(),
            BotTypes::GOOGLE.bits()
                | BotTypes::BING.bits()
                | BotTypes::BAIDU.bits()
                | BotTypes::SOGOU.bits()
                | BotTypes::YANDEX.bits()
        );
    }
}
