#[derive(Debug)]
pub struct WsHeaders<'a> {
    upgrade: Option<&'a str>,
    websocket_key: Option<&'a str>,
}
impl<'a> WsHeaders<'a> {
    pub fn new() -> Self {
        Self {
            upgrade: None,
            websocket_key: None,
        }
    }
    pub fn get(&self, key: &str) -> Option<&'a str> {
        match key {
            "Upgrade" => self.get_upgrade(),
            "Sec-WebSocket-Key" => self.get_key(),
            _ => None,
        }
    }
    pub fn get_upgrade(&self) -> Option<&'a str> {
        self.upgrade
    }
    pub fn get_key(&self) -> Option<&'a str> {
        self.websocket_key
    }
    pub fn is_websocket(&self) -> bool {
        matches!(self.upgrade, Some("websocket"))
    }
    pub fn has_key(&self) -> bool {
        matches!(self.upgrade, Some(_))
    }
}
fn get_ws_headers_from_str<'a>(input: &'a str) -> WsHeaders<'a> {
    let mut ws_headers = WsHeaders::new();
    input.split("\r\n").for_each(|row| {
        let mut splits = row.splitn(2, ": ");
        match (splits.next(), splits.next()) {
            (Some("Upgrade"), value) => ws_headers.upgrade = value,
            (Some("Sec-WebSocket-Key"), value) => ws_headers.websocket_key = value,
            _ => {}
        }
    });

    ws_headers
}
impl<'a> From<&'a str> for WsHeaders<'a> {
    fn from(input: &'a str) -> Self {
        get_ws_headers_from_str(input)
    }
}
impl<'a> From<&'a std::borrow::Cow<'a, str>> for WsHeaders<'a> {
    fn from(input: &'a std::borrow::Cow<'a, str>) -> WsHeaders<'a> {
        get_ws_headers_from_str(&input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    const BUFFER: [u8; 503] = {
        [
            71, 69, 84, 32, 47, 32, 72, 84, 84, 80, 47, 49, 46, 49, 13, 10, 72, 111, 115, 116, 58,
            32, 91, 58, 58, 49, 93, 58, 51, 51, 51, 51, 13, 10, 85, 115, 101, 114, 45, 65, 103,
            101, 110, 116, 58, 32, 77, 111, 122, 105, 108, 108, 97, 47, 53, 46, 48, 32, 40, 87,
            105, 110, 100, 111, 119, 115, 32, 78, 84, 32, 49, 48, 46, 48, 59, 32, 87, 105, 110, 54,
            52, 59, 32, 120, 54, 52, 59, 32, 114, 118, 58, 56, 51, 46, 48, 41, 32, 71, 101, 99,
            107, 111, 47, 50, 48, 49, 48, 48, 49, 48, 49, 32, 70, 105, 114, 101, 102, 111, 120, 47,
            56, 51, 46, 48, 13, 10, 65, 99, 99, 101, 112, 116, 58, 32, 42, 47, 42, 13, 10, 65, 99,
            99, 101, 112, 116, 45, 76, 97, 110, 103, 117, 97, 103, 101, 58, 32, 115, 118, 45, 83,
            69, 44, 115, 118, 59, 113, 61, 48, 46, 56, 44, 101, 110, 45, 85, 83, 59, 113, 61, 48,
            46, 53, 44, 101, 110, 59, 113, 61, 48, 46, 51, 13, 10, 65, 99, 99, 101, 112, 116, 45,
            69, 110, 99, 111, 100, 105, 110, 103, 58, 32, 103, 122, 105, 112, 44, 32, 100, 101,
            102, 108, 97, 116, 101, 13, 10, 83, 101, 99, 45, 87, 101, 98, 83, 111, 99, 107, 101,
            116, 45, 86, 101, 114, 115, 105, 111, 110, 58, 32, 49, 51, 13, 10, 79, 114, 105, 103,
            105, 110, 58, 32, 109, 111, 122, 45, 101, 120, 116, 101, 110, 115, 105, 111, 110, 58,
            47, 47, 55, 50, 48, 99, 48, 50, 54, 48, 45, 97, 99, 56, 51, 45, 52, 102, 100, 101, 45,
            98, 100, 53, 102, 45, 101, 51, 51, 49, 50, 55, 102, 100, 57, 101, 50, 98, 13, 10, 83,
            101, 99, 45, 87, 101, 98, 83, 111, 99, 107, 101, 116, 45, 69, 120, 116, 101, 110, 115,
            105, 111, 110, 115, 58, 32, 112, 101, 114, 109, 101, 115, 115, 97, 103, 101, 45, 100,
            101, 102, 108, 97, 116, 101, 13, 10, 83, 101, 99, 45, 87, 101, 98, 83, 111, 99, 107,
            101, 116, 45, 75, 101, 121, 58, 32, 43, 88, 49, 72, 80, 102, 74, 51, 74, 48, 90, 118,
            80, 97, 70, 104, 108, 113, 73, 65, 109, 103, 61, 61, 13, 10, 67, 111, 110, 110, 101,
            99, 116, 105, 111, 110, 58, 32, 107, 101, 101, 112, 45, 97, 108, 105, 118, 101, 44, 32,
            85, 112, 103, 114, 97, 100, 101, 13, 10, 80, 114, 97, 103, 109, 97, 58, 32, 110, 111,
            45, 99, 97, 99, 104, 101, 13, 10, 67, 97, 99, 104, 101, 45, 67, 111, 110, 116, 114,
            111, 108, 58, 32, 110, 111, 45, 99, 97, 99, 104, 101, 13, 10, 85, 112, 103, 114, 97,
            100, 101, 58, 32, 119, 101, 98, 115, 111, 99, 107, 101, 116, 13, 10, 13, 10,
        ]
    };
    // This is how you could write a naive HashMap of HTTP requests
    fn get_headers_from_str<'a>(input: &'a str) -> HashMap<&'a str, &'a str> {
        input
            .split("\r\n")
            .flat_map(|row| {
                let mut splits = row.splitn(2, ": ");
                match (splits.next(), splits.next()) {
                    (Some(key), Some(value)) => Some((key, value)),
                    _ => None,
                }
            })
            .collect()
    }
    #[test]
    fn should_convert_properly() {
        let input = String::from_utf8_lossy(&BUFFER);
        let result = get_headers_from_str(&input);
        assert_eq!(result.get("Sec-WebSocket-Version"), Some(&"13"));
        assert_eq!(result.get("Accept"), Some(&"*/*"));
        assert_eq!(
            result.get("Accept-Language"),
            Some(&"sv-SE,sv;q=0.8,en-US;q=0.5,en;q=0.3")
        );
        assert_eq!(
            result.get("Origin"),
            Some(&"moz-extension://720c0260-ac83-4fde-bd5f-e33127fd9e2b")
        );
        assert_eq!(
            result.get("Sec-WebSocket-Extensions"),
            Some(&"permessage-deflate")
        );
        assert_eq!(
            result.get("Sec-WebSocket-Key"),
            Some(&"+X1HPfJ3J0ZvPaFhlqIAmg==")
        );
        assert_eq!(result.get("Connection"), Some(&"keep-alive, Upgrade"));
        assert_eq!(result.get("Pragma"), Some(&"no-cache"));
        assert_eq!(result.get("Cache-Control"), Some(&"no-cache"));
        assert_eq!(result.get("Host"), Some(&"[::1]:3333"));
        assert_eq!(result.get("Upgrade"), Some(&"websocket"));
        assert_eq!(
            result.get("User-Agent"),
            Some(&"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:83.0) Gecko/20100101 Firefox/83.0")
        );
        assert_eq!(result.get("Accept-Encoding"), Some(&"gzip, deflate"));
    }
    #[test]
    fn should_convert_properly_ws_headers() {
        let input = String::from_utf8_lossy(&BUFFER);
        let result = get_ws_headers_from_str(&input);
        assert_eq!(
            result.get("Sec-WebSocket-Key"),
            Some("+X1HPfJ3J0ZvPaFhlqIAmg==")
        );
        assert_eq!(result.get("Upgrade"), Some("websocket"));
    }
    #[cfg(feature = "count-allocations")]
    #[test]
    fn should_barely_allocate_anything() {
        let pt_alloc = allocation_counter::count(|| {
            let input = String::from_utf8_lossy(&BUFFER);
            let _result = get_headers_from_str(&input);
        });
        assert_eq!(pt_alloc, 3);
    }
    #[cfg(feature = "count-allocations")]
    #[test]
    fn should_not_allocate_anything() {
        let pt_alloc = allocation_counter::count(|| {
            let input = String::from_utf8_lossy(&BUFFER);
            let _result = get_ws_headers_from_str(&input);
        });
        assert_eq!(pt_alloc, 0);
    }
}
