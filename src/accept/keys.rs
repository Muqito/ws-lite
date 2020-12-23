use crate::accept::ws_headers::WsHeaders;
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
fn get_response_key(key: &[u8; 24]) -> [u8; 28] {
    let mut buff: [u8; 28] = [0; 28];
    let sha1_response_key = sha1_bytes(concat_key(key, MAGIC_GUID).as_slice());
    base64::encode_config_slice(sha1_response_key, base64::STANDARD, &mut buff);
    buff
}
fn get_accept_response(response_key: &[u8; 28]) -> [u8; 129] {
    concat_accept_response_from_response_key(ACCEPT_HEADER, &response_key, HTTP_EOC)
}

#[derive(Debug)]
pub enum KeyError {
    Unknown,
    InvalidPayload,
}
pub struct HeaderBuffers;
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

fn buffer_to_response_key<B>(input: B) -> Result<AcceptResponse, KeyError>
where
    B: AsRef<[u8]>,
{
    let input = String::from_utf8_lossy(B::as_ref(&input));
    let headers = WsHeaders::from(&input);
    match (headers.get("Upgrade"), headers.get("Sec-WebSocket-Key")) {
        (Some("websocket"), Some(key)) => AcceptResponse::try_from(key.as_bytes()),
        _ => Err(KeyError::InvalidPayload),
    }
}
pub trait FromHeaderBuffer {
    type Error;
    fn from_header_buffer(input: &[u8]) -> Result<Self, <Self as FromBuffer<HeaderBuffers>>::Error>
    where
        Self: Sized,
        Self: FromBuffer<HeaderBuffers>,
    {
        <Self as FromBuffer<HeaderBuffers>>::from_buffer(input)
    }
}
impl AcceptResponse {
    pub fn get_data(&self) -> &[u8] {
        &self.0
    }
}
impl FromHeaderBuffer for AcceptKey {
    type Error = KeyError;
}
impl FromHeaderBuffer for ResponseKey {
    type Error = KeyError;
}
impl FromHeaderBuffer for AcceptResponse {
    type Error = KeyError;
}
impl AsRef<[u8]> for AcceptResponse {
    fn as_ref(&self) -> &[u8] {
        self.get_data()
    }
}
pub trait FromBuffer<T> {
    type Error;
    fn from_buffer(input: &[u8]) -> Result<Self, Self::Error>
    where
        Self: Sized;
}

impl FromBuffer<HeaderBuffers> for AcceptKey {
    type Error = KeyError;

    fn from_buffer(input: &[u8]) -> Result<Self, Self::Error> {
        input
            .try_into()
            .map(AcceptKey)
            .map_err(|_| KeyError::InvalidPayload)
    }
}
impl FromBuffer<HeaderBuffers> for ResponseKey {
    type Error = KeyError;

    fn from_buffer(input: &[u8]) -> Result<Self, Self::Error> {
        /*        input
        .try_into()
        .map(AcceptKey)
        .map(ResponseKey::from)
        .map_err(|_| KeyError::InvalidPayload)*/
        <AcceptKey as FromBuffer<HeaderBuffers>>::from_buffer(input)
            .map(ResponseKey::from)
            .map_err(|_| KeyError::InvalidPayload)
    }
}
impl FromBuffer<HeaderBuffers> for AcceptResponse {
    type Error = KeyError;

    fn from_buffer(input: &[u8]) -> Result<Self, Self::Error> {
        buffer_to_response_key(&input)
    }
}
impl FromBuffer<ResponseKey> for ResponseKey {
    type Error = KeyError;

    fn from_buffer(input: &[u8]) -> Result<Self, Self::Error> {
        input
            .try_into()
            .map(ResponseKey)
            .map_err(|_| KeyError::InvalidPayload)
    }
}
impl FromBuffer<ResponseKey> for AcceptResponse {
    type Error = KeyError;

    fn from_buffer(input: &[u8]) -> Result<Self, Self::Error> {
        <ResponseKey as FromBuffer<ResponseKey>>::from_buffer(&input).map(AcceptResponse::from)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
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

        let rk =
            <ResponseKey as FromBuffer<ResponseKey>>::from_buffer(response_key.as_slice()).unwrap();
        let rk2 = <ResponseKey as FromBuffer<ResponseKey>>::from_buffer(response_key2.as_slice())
            .unwrap();
        assert_eq!(rk.0, response_key);
        assert_eq!(rk2.0, response_key2);

        let ar = <AcceptResponse as FromBuffer<ResponseKey>>::from_buffer(response_key.as_slice())
            .unwrap();
        let ar2 =
            <AcceptResponse as FromBuffer<ResponseKey>>::from_buffer(response_key2.as_slice())
                .unwrap();
        assert_eq!(ar.0, expected_result);
        assert_eq!(ar2.0, expected_result2);
    }
}
