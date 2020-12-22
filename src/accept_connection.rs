use const_sha1::{sha1, ConstBuffer};
use std::convert::{TryFrom, TryInto};

const MAGIC_GUID: &[u8; 36] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const ACCEPT_HEADER: &[u8; 97] = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-Websocket-Accept: ";
const HTTP_EOC: &[u8; 4] = b"\r\n\r\n";

fn sha1_bytes<D>(data: D) -> [u8; 20]
where
    D: AsRef<[u8]>,
{
    sha1(&ConstBuffer::from_slice(D::as_ref(&data))).bytes()
}

fn concat_accept_response_from_response_key(a: &[u8; 97], b: &[u8; 28], c: &[u8; 4]) -> [u8; 129] {
    let mut output: [u8; 129] = [0; 129];
    output[0..97].copy_from_slice(a);
    output[97..125].copy_from_slice(b);
    output[125..129].copy_from_slice(c);
    output
}
fn concat_key(a: &[u8; 24], b: &[u8; 36]) -> [u8; 60] {
    let mut output: [u8; 60] = [0; 60];
    output[0..24].copy_from_slice(a);
    output[24..60].copy_from_slice(b);
    output
}
pub fn get_response_key(key: &[u8; 24]) -> [u8; 28] {
    let mut buff: [u8; 28] = [0; 28];
    let sha1_response_key = sha1_bytes(concat_key(key, MAGIC_GUID).as_slice());
    base64::encode_config_slice(sha1_response_key, base64::STANDARD, &mut buff);
    buff
}

pub fn get_accept_response(response_key: &[u8; 28]) -> [u8; 129] {
    concat_accept_response_from_response_key(ACCEPT_HEADER, &response_key, HTTP_EOC)
}
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

// --------------
#[derive(Debug)]
pub enum KeyError {
    Unknown,
    InvalidPayload,
}
#[derive(Debug, PartialEq)]
pub struct AcceptKey([u8; 24]);
#[derive(Debug, PartialEq)]
pub struct ResponseKey([u8; 28]);
#[derive(Debug, PartialEq)]
pub struct AcceptResponse([u8; 129]);

impl AcceptKey {
    fn try_parse<'a>(data: &'a [u8]) -> Option<AcceptKey> {
        AcceptKey::try_from(data).ok()
    }
}
impl From<ResponseKey> for AcceptResponse {
    fn from(response_key: ResponseKey) -> Self {
        AcceptResponse(get_accept_response(&response_key.0))
    }
}
impl From<AcceptKey> for ResponseKey {
    fn from(accept_key: AcceptKey) -> Self {
        ResponseKey(get_response_key(&accept_key.0))
    }
}

impl<'a> TryFrom<&'a [u8]> for AcceptKey {
    type Error = KeyError;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        value
            .try_into()
            .map(AcceptKey)
            .map_err(|_| KeyError::InvalidPayload)
    }
}
impl<'a> TryFrom<&'a [u8]> for ResponseKey {
    type Error = KeyError;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        AcceptKey::try_from(value).map(ResponseKey::from)
    }
}
impl<'a> TryFrom<&'a [u8]> for AcceptResponse {
    type Error = KeyError;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        ResponseKey::try_from(value).map(AcceptResponse::from)
    }
}
impl<'a> From<WsHeaders<'a>> for Option<AcceptKey> {
    fn from(headers: WsHeaders<'a>) -> Option<AcceptKey> {
        match (headers.get("Upgrade"), headers.get("Sec-WebSocket-Key")) {
            (Some("websocket"), Some(key)) => AcceptKey::try_parse(key.as_bytes()),
            _ => None,
        }
    }
}
impl<'a> From<WsHeaders<'a>> for Option<AcceptResponse> {
    fn from(headers: WsHeaders<'a>) -> Option<AcceptResponse> {
        match (headers.get("Upgrade"), headers.get("Sec-WebSocket-Key")) {
            (Some("websocket"), Some(key)) => AcceptResponse::try_from(key.as_bytes()).ok(),
            _ => None,
        }
    }
}

pub fn buffer_to_response_key<B>(input: B) -> Option<AcceptResponse>
where
    B: AsRef<[u8]>,
{
    let input = String::from_utf8_lossy(B::as_ref(&input));
    let headers = WsHeaders::from(&input);
    Option::<AcceptResponse>::from(headers)
}

impl AcceptResponse {
    pub fn from_buffer(input: &[u8]) -> Option<AcceptResponse> {
        buffer_to_response_key(input)
    }
    pub fn get_data(&self) -> &[u8] {
        &self.0
    }
}
impl AsRef<[u8]> for AcceptResponse {
    fn as_ref(&self) -> &[u8] {
        self.get_data()
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
    #[test]
    fn should_get_accept_response() {
        let expected_result = {
            [
                72, 84, 84, 80, 47, 49, 46, 49, 32, 49, 48, 49, 32, 83, 119, 105, 116, 99, 104,
                105, 110, 103, 32, 80, 114, 111, 116, 111, 99, 111, 108, 115, 13, 10, 85, 112, 103,
                114, 97, 100, 101, 58, 32, 119, 101, 98, 115, 111, 99, 107, 101, 116, 13, 10, 67,
                111, 110, 110, 101, 99, 116, 105, 111, 110, 58, 32, 85, 112, 103, 114, 97, 100,
                101, 13, 10, 83, 101, 99, 45, 87, 101, 98, 115, 111, 99, 107, 101, 116, 45, 65, 99,
                99, 101, 112, 116, 58, 32, 71, 97, 43, 48, 48, 71, 98, 68, 77, 53, 103, 68, 77, 73,
                112, 118, 75, 97, 122, 78, 86, 105, 118, 103, 116, 57, 115, 61, 13, 10, 13, 10,
            ]
        };
        let expected_result2 = {
            [
                72, 84, 84, 80, 47, 49, 46, 49, 32, 49, 48, 49, 32, 83, 119, 105, 116, 99, 104,
                105, 110, 103, 32, 80, 114, 111, 116, 111, 99, 111, 108, 115, 13, 10, 85, 112, 103,
                114, 97, 100, 101, 58, 32, 119, 101, 98, 115, 111, 99, 107, 101, 116, 13, 10, 67,
                111, 110, 110, 101, 99, 116, 105, 111, 110, 58, 32, 85, 112, 103, 114, 97, 100,
                101, 13, 10, 83, 101, 99, 45, 87, 101, 98, 115, 111, 99, 107, 101, 116, 45, 65, 99,
                99, 101, 112, 116, 58, 32, 89, 83, 101, 78, 70, 103, 79, 80, 73, 106, 85, 43, 77,
                84, 53, 49, 49, 120, 103, 116, 87, 111, 73, 53, 43, 69, 77, 61, 13, 10, 13, 10,
            ]
        };
        let response_key = {
            [
                71, 97, 43, 48, 48, 71, 98, 68, 77, 53, 103, 68, 77, 73, 112, 118, 75, 97, 122, 78,
                86, 105, 118, 103, 116, 57, 115, 61,
            ]
        };
        let response_key2 = {
            [
                89, 83, 101, 78, 70, 103, 79, 80, 73, 106, 85, 43, 77, 84, 53, 49, 49, 120, 103,
                116, 87, 111, 73, 53, 43, 69, 77, 61,
            ]
        };

        let result = get_accept_response(&response_key);
        let result2 = get_accept_response(&response_key2);
        assert_eq!(result, expected_result);
        assert_eq!(result2, expected_result2);
    }
    #[cfg(feature = "count-allocations")]
    #[test]
    fn response_keys_no_allocations() {
        let pt_alloc = allocation_counter::count(|| {
            let response_key2 = {
                [
                    89, 83, 101, 78, 70, 103, 79, 80, 73, 106, 85, 43, 77, 84, 53, 49, 49, 120,
                    103, 116, 87, 111, 73, 53, 43, 69, 77, 61,
                ]
            };
            let response_key = {
                [
                    71, 97, 43, 48, 48, 71, 98, 68, 77, 53, 103, 68, 77, 73, 112, 118, 75, 97, 122,
                    78, 86, 105, 118, 103, 116, 57, 115, 61,
                ]
            };

            get_accept_response(&response_key);
            get_accept_response(&response_key2);
        });
        assert_eq!(pt_alloc, 0);
    }
    #[test]
    fn should_convert_from_buffer_to_accept_response() {
        let expected_result = {
            [
                72, 84, 84, 80, 47, 49, 46, 49, 32, 49, 48, 49, 32, 83, 119, 105, 116, 99, 104,
                105, 110, 103, 32, 80, 114, 111, 116, 111, 99, 111, 108, 115, 13, 10, 85, 112, 103,
                114, 97, 100, 101, 58, 32, 119, 101, 98, 115, 111, 99, 107, 101, 116, 13, 10, 67,
                111, 110, 110, 101, 99, 116, 105, 111, 110, 58, 32, 85, 112, 103, 114, 97, 100,
                101, 13, 10, 83, 101, 99, 45, 87, 101, 98, 115, 111, 99, 107, 101, 116, 45, 65, 99,
                99, 101, 112, 116, 58, 32, 71, 97, 43, 48, 48, 71, 98, 68, 77, 53, 103, 68, 77, 73,
                112, 118, 75, 97, 122, 78, 86, 105, 118, 103, 116, 57, 115, 61, 13, 10, 13, 10,
            ]
        };
        let expected_result2 = {
            [
                72, 84, 84, 80, 47, 49, 46, 49, 32, 49, 48, 49, 32, 83, 119, 105, 116, 99, 104,
                105, 110, 103, 32, 80, 114, 111, 116, 111, 99, 111, 108, 115, 13, 10, 85, 112, 103,
                114, 97, 100, 101, 58, 32, 119, 101, 98, 115, 111, 99, 107, 101, 116, 13, 10, 67,
                111, 110, 110, 101, 99, 116, 105, 111, 110, 58, 32, 85, 112, 103, 114, 97, 100,
                101, 13, 10, 83, 101, 99, 45, 87, 101, 98, 115, 111, 99, 107, 101, 116, 45, 65, 99,
                99, 101, 112, 116, 58, 32, 89, 83, 101, 78, 70, 103, 79, 80, 73, 106, 85, 43, 77,
                84, 53, 49, 49, 120, 103, 116, 87, 111, 73, 53, 43, 69, 77, 61, 13, 10, 13, 10,
            ]
        };
        let response_key = {
            [
                71, 97, 43, 48, 48, 71, 98, 68, 77, 53, 103, 68, 77, 73, 112, 118, 75, 97, 122, 78,
                86, 105, 118, 103, 116, 57, 115, 61,
            ]
        };
        let response_key2 = {
            [
                89, 83, 101, 78, 70, 103, 79, 80, 73, 106, 85, 43, 77, 84, 53, 49, 49, 120, 103,
                116, 87, 111, 73, 53, 43, 69, 77, 61,
            ]
        };

        let rk = ResponseKey::try_from(response_key.as_slice()).unwrap();
        let rk2 = ResponseKey::try_from(response_key2.as_slice()).unwrap();
        assert_eq!(rk.0, response_key);
        assert_eq!(rk2.0, response_key2);

        let ar = AcceptResponse::try_from(response_key.as_slice()).unwrap();
        let ar2 = AcceptResponse::try_from(response_key2.as_slice()).unwrap();
        assert_eq!(ar.0, expected_result);
        assert_eq!(ar2.0, expected_result2);
    }
}
