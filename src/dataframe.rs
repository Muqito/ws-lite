use std::borrow::Cow;

pub fn mask_data<const N: usize>(data: &mut [u8], mask: [u8; N]) {
    for index in 0..data.len() {
        data[index] ^= mask[index % N];
    }
}
#[derive(PartialEq)]
pub enum Opcode {
    Continuation = 0,
    Text = 1,
    Binary = 2,
    Close = 8,
    Ping = 9,
    Pong = 10,
    Unknown,
}
impl From<u8> for Opcode {
    fn from(v: u8) -> Opcode {
        match v {
            0 => Opcode::Continuation,
            1 => Opcode::Text,
            8 => Opcode::Close,
            9 => Opcode::Ping,
            10 => Opcode::Pong,
            _ => Opcode::Unknown,
        }
    }
}

#[derive(Debug)]
pub enum ExtraSize {
    Zero(u8),
    Two,
    Eight,
}
pub mod frame_positions {
    // Frame one
    pub const FIN: u8 = 128;
    pub const RSV1: u8 = 64;
    pub const RSV2: u8 = 32;
    pub const RSV3: u8 = 16;
    pub const MASK_OPCODE: u8 = 0b00001111;
    // Frame two
    pub const IS_MASK: u8 = 128;
    pub const MASK_PAYLOAD_LENGTH: u8 = 0b01111111;
}

#[derive(Debug)]
pub enum ReadMessage<'a> {
    Text(Cow<'a, str>),
    Binary(&'a [u8]),
    Ping(&'a [u8]),
    Pong(&'a [u8]),
    Close,
}

#[derive(Debug)]
pub struct DataFrame {
    data: Vec<u8>,
}
impl DataFrame {
    pub fn new(data: Vec<u8>) -> DataFrame {
        let mut dataframe = DataFrame { data };

        dataframe.calculate_masked_data();

        dataframe
    }
    #[inline(always)]
    pub fn is_fin(&self) -> bool {
        self.data
            .get(0)
            .map(|frame| (frame & frame_positions::FIN) == frame_positions::FIN)
            .unwrap_or(false)
    }
    #[inline(always)]
    pub fn is_rsv1(&self) -> bool {
        self.data
            .get(0)
            .map(|frame| (frame & frame_positions::RSV1) == frame_positions::RSV1)
            .unwrap_or(false)
    }
    #[inline(always)]
    pub fn is_rsv2(&self) -> bool {
        self.data
            .get(0)
            .map(|frame| (frame & frame_positions::RSV2) == frame_positions::RSV2)
            .unwrap_or(false)
    }
    #[inline(always)]
    pub fn is_rsv3(&self) -> bool {
        self.data
            .get(0)
            .map(|frame| (frame & frame_positions::RSV3) == frame_positions::RSV3)
            .unwrap_or(false)
    }
    #[inline(always)]
    /// Get the last four bits in one byte in first frame
    pub fn get_opcode(&self) -> u8 {
        // default to close
        self.data
            .get(0)
            .map(|frame| frame & frame_positions::MASK_OPCODE)
            .unwrap_or(8)
    }
    #[inline(always)]
    pub fn is_mask(&self) -> bool {
        self.data
            .get(1)
            .map(|frame| (frame & frame_positions::IS_MASK) == frame_positions::IS_MASK)
            .unwrap_or(false)
    }
    /// Get the last seven bits in the byte in the second frame
    #[inline(always)]
    fn get_short_payload_length(&self) -> u8 {
        self.data
            .get(1)
            .map(|frame| frame & frame_positions::MASK_PAYLOAD_LENGTH)
            .unwrap_or(0)
    }
    #[inline(always)]
    fn get_extra_payload_bytes(&self) -> ExtraSize {
        match self.get_short_payload_length() {
            size @ 0..=125 => ExtraSize::Zero(size),
            126 => ExtraSize::Two,
            127 => ExtraSize::Eight,
            _ => unreachable!("We are only working with sizes up to the far most left bit"),
        }
    }
    #[inline(always)]
    pub fn get_payload_length(&self) -> usize {
        match self.get_extra_payload_bytes() {
            ExtraSize::Zero(size) => size as usize,
            ExtraSize::Two if self.data.len() > 4 => {
                let mut bytes: [u8; 2] = [0; 2];
                bytes.copy_from_slice(&self.data[2..4]);
                u16::from_be_bytes(bytes) as usize
            }
            ExtraSize::Eight if self.data.len() > 8 => {
                let mut bytes: [u8; 8] = [0; 8];
                bytes.copy_from_slice(&self.data[2..10]);
                u64::from_be_bytes(bytes) as usize
            }
            _ => 0,
        }
    }

    fn get_payload_start_pos(&self) -> usize {
        match self.get_extra_payload_bytes() {
            ExtraSize::Zero(_) => 6,
            ExtraSize::Two => 8,
            ExtraSize::Eight => 14,
        }
    }
    pub fn get_full_frame_length(&self) -> usize {
        self.get_payload_start_pos() + self.get_payload_length()
    }
    #[inline(always)]
    fn get_masking_key_start(&self) -> u8 {
        2 + match self.get_extra_payload_bytes() {
            ExtraSize::Zero(_) => 0,
            ExtraSize::Two => 2,
            ExtraSize::Eight => 8,
        }
    }
    #[inline(always)]
    pub fn get_masking_key(&self) -> [u8; 4] {
        let start = self.get_masking_key_start() as usize;
        let end = start + 4;
        if self.is_mask() && self.data.len() >= end {
            let mut buffer: [u8; 4] = [0; 4];
            buffer.copy_from_slice(&self.data[start..end]);
            buffer
        } else {
            // masking key [0, 0, 0, 0] is ok because 1 ^ 0 == 1, 0 ^ 0 == 0
            [0, 0, 0, 0]
        }
    }
    fn get_start_and_end_payload(&self) -> Option<(usize, usize)> {
        let start_payload = self.get_payload_start_pos();
        let payload_length = self.get_payload_length();

        if start_payload > self.data.len() {
            return None;
        }
        let end_payload = start_payload + payload_length;

        if end_payload > self.data.len() {
            return None;
        }

        Some((start_payload, end_payload))
    }
    pub fn get_full_payload(&self) -> &[u8] {
        &self.data
    }
    #[inline(always)]
    pub fn get_payload(&self) -> Option<&[u8]> {
        if Opcode::from(self.get_opcode()) == Opcode::Close {
            return None;
        }

        let (start, end) = match self.get_start_and_end_payload() {
            Some(x) => x,
            None => return None,
        };

        if end > start {
            Some(&self.data[start..end])
        } else {
            None
        }
    }
    pub fn text(&self) -> Option<Cow<'_, str>> {
        self.get_payload().map(String::from_utf8_lossy)
    }
    pub fn binary(&self) -> Option<&[u8]> {
        self.get_payload()
    }
    pub fn is_closed(&self) -> bool {
        let opcode = Opcode::from(self.get_opcode());
        matches!(opcode, Opcode::Close)
    }
    fn calculate_masked_data(&mut self) {
        if let Some((start_payload, end_payload)) = self.get_start_and_end_payload() {
            let mask = self.get_masking_key();
            mask_data(&mut self.data[start_payload..end_payload], mask);
        }
    }
    pub fn get_message<'b>(&'b self) -> Option<ReadMessage<'b>> {
        match Opcode::from(self.get_opcode()) {
            Opcode::Ping => self.binary().map(ReadMessage::Ping),
            Opcode::Pong => self.binary().map(ReadMessage::Pong),
            Opcode::Binary => self.binary().map(ReadMessage::Binary),
            Opcode::Text => self.text().map(ReadMessage::Text),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{Message, WriteMessage};

    #[test]
    fn test_from_message_a() {
        let payload = WriteMessage::from(Message::Text(String::from("a")));
        let data = payload.get_output();
        assert_eq!(data.len(), 3);
        assert_eq!(data, &vec![129, 1, 97]);
    }
    #[test]
    fn test_from_message_aa() {
        let payload = WriteMessage::from(Message::Text(String::from("aa")));
        let data = payload.get_output();
        assert_eq!(data.len(), 4);
        assert_eq!(data, &vec![129, 2, 97, 97]);
    }
    #[test]
    fn test_buffer_hello_world() {
        let str = "Hello World";
        let buffer: Vec<u8> = vec![
            129, 139, 90, 212, 118, 181, 18, 177, 26, 217, 53, 244, 33, 218, 40, 184, 18,
        ];
        let dataframe = DataFrame::new(buffer);

        assert!(dataframe.is_fin());
        assert!(dataframe.is_mask());

        let input = String::from_utf8_lossy(dataframe.get_payload().unwrap());
        assert_eq!(input, str);
    }
    #[test]
    #[should_panic]
    fn test_buffer_with_no_payload_or_masking_key_but_payload_length() {
        let buffer: Vec<u8> = vec![
            129, // FIN(128) + Opcode(1)
            129, // MASK(128) + PayloadLength(1)
        ];
        let dataframe = DataFrame::new(buffer);

        assert_eq!(dataframe.get_payload_length(), 1);
        assert_eq!(dataframe.get_full_payload(), Vec::<u8>::new());
    }
    #[test]
    fn test_buffer_with_no_payload_but_masking_key_and_payload_length() {
        let buffer: Vec<u8> = vec![
            129, // FIN(128) + Opcode(1)
            129, // MASK(128) + PayloadLength(1)
            0, 0, 0, 0,
        ];
        let dataframe = DataFrame::new(buffer);
        assert_eq!(dataframe.get_payload_length(), 1);
        assert_eq!(dataframe.get_masking_key(), [0, 0, 0, 0]);
        assert_eq!(dataframe.get_payload(), None);
    }
    #[test]
    fn test_buffer_with_no_payload_or_mask() {
        let buffer: Vec<u8> = vec![
            129, // FIN(128) + Opcode(1)
            0,
        ];
        let dataframe = DataFrame::new(buffer);
        assert_eq!(dataframe.get_payload_length(), 0);
        assert_eq!(dataframe.get_masking_key(), [0, 0, 0, 0]);
        assert_eq!(dataframe.get_payload(), None);
    }
    #[test]
    fn test_close_frame_from_client() {
        let buffer: Vec<u8> = vec![
            136, // FIN(128) + Opcode(8)
            128, // MASK(128)
        ];
        let dataframe = DataFrame::new(buffer);
        assert!(dataframe.is_fin());
        assert_eq!(dataframe.get_masking_key(), [0, 0, 0, 0]);
        assert_eq!(dataframe.get_payload(), None);
    }
    #[test]
    fn test_buffer_with_no_payload_with_masking_key() {
        let buffer: Vec<u8> = vec![
            129, // FIN(128) + Opcode(1)
            128, // MASK(128)
            0, 0, 0, 0,
        ];
        let dataframe = DataFrame::new(buffer);
        assert!(dataframe.is_fin());
        assert_eq!(dataframe.get_masking_key(), [0, 0, 0, 0]);
        assert_eq!(dataframe.get_payload(), None);
    }
    #[test]
    fn test_buffer_126_length() {
        let str = "xZHtBeHbpCWCTCozNw0GxAdQ8Qqqtex5Zje8FBaVQpxrigx92BpLYYiXZnAA70CdNslWvgdSMz0vfUggF8U8wrULZz7ns1tUi5BDWmxx0XS5LsBeyFuaCq4NDAvwbi";
        let buffer: Vec<u8> = vec![
            129, 254, 0, 126, 202, 250, 57, 41, 178, 160, 113, 93, 136, 159, 113, 75, 186, 185,
            110, 106, 158, 185, 86, 83, 132, 141, 9, 110, 178, 187, 93, 120, 242, 171, 72, 88, 190,
            159, 65, 28, 144, 144, 92, 17, 140, 184, 88, 127, 155, 138, 65, 91, 163, 157, 65, 16,
            248, 184, 73, 101, 147, 163, 80, 113, 144, 148, 120, 104, 253, 202, 122, 77, 132, 137,
            85, 126, 188, 157, 93, 122, 135, 128, 9, 95, 172, 175, 94, 78, 140, 194, 108, 17, 189,
            136, 108, 101, 144, 128, 14, 71, 185, 203, 77, 124, 163, 207, 123, 109, 157, 151, 65,
            81, 250, 162, 106, 28, 134, 137, 123, 76, 179, 188, 76, 72, 137, 139, 13, 103, 142,
            187, 79, 94, 168, 147,
        ];
        let dataframe = DataFrame::new(buffer);
        let input = String::from_utf8_lossy(dataframe.get_payload().unwrap());
        assert_eq!(input, str);
    }
    #[test]
    fn test_buffer_126_overflow_length() {
        let str = "xZHtBeHbpCWCTCozNw0GxAdQ8Qqqtex5Zje8FBaVQpxrigx92BpLYYiXZnAA70CdNslWvgdSMz0vfUggF8U8wrULZz7ns1tUi5BDWmxx0XS5LsBeyFuaCq4NDAvwbi";
        let buffer: Vec<u8> = vec![
            129, 254, 0, 126, 202, 250, 57, 41, 178, 160, 113, 93, 136, 159, 113, 75, 186, 185,
            110, 106, 158, 185, 86, 83, 132, 141, 9, 110, 178, 187, 93, 120, 242, 171, 72, 88, 190,
            159, 65, 28, 144, 144, 92, 17, 140, 184, 88, 127, 155, 138, 65, 91, 163, 157, 65, 16,
            248, 184, 73, 101, 147, 163, 80, 113, 144, 148, 120, 104, 253, 202, 122, 77, 132, 137,
            85, 126, 188, 157, 93, 122, 135, 128, 9, 95, 172, 175, 94, 78, 140, 194, 108, 17, 189,
            136, 108, 101, 144, 128, 14, 71, 185, 203, 77, 124, 163, 207, 123, 109, 157, 151, 65,
            81, 250, 162, 106, 28, 134, 137, 123, 76, 179, 188, 76, 72, 137, 139, 13, 103, 142,
            187, 79, 94, 168, 147, 0, 0, 0, 0,
        ];
        let dataframe = DataFrame::new(buffer);
        let input = String::from_utf8_lossy(dataframe.get_payload().unwrap());

        assert_eq!(input, str);
    }
    #[test]
    fn test_buffer_127_length() {
        let str = "xZHtBeHbpCWCTCozNw0GxAdQ8Qqqtex5Zje8FBaVQpxrigx92BpLYYiXZnAA70CdNslWvgdSMz0vfUggF8U8wrULZz7ns1tUi5BDWmxx0XS5LsBeyFuaCq4NDAvwbia";
        let buffer: Vec<u8> = vec![
            129, 254, 0, 127, 238, 233, 37, 50, 150, 179, 109, 70, 172, 140, 109, 80, 158, 170,
            114, 113, 186, 170, 74, 72, 160, 158, 21, 117, 150, 168, 65, 99, 214, 184, 84, 67, 154,
            140, 93, 7, 180, 131, 64, 10, 168, 171, 68, 100, 191, 153, 93, 64, 135, 142, 93, 11,
            220, 171, 85, 126, 183, 176, 76, 106, 180, 135, 100, 115, 217, 217, 102, 86, 160, 154,
            73, 101, 152, 142, 65, 97, 163, 147, 21, 68, 136, 188, 66, 85, 168, 209, 112, 10, 153,
            155, 112, 126, 180, 147, 18, 92, 157, 216, 81, 103, 135, 220, 103, 118, 185, 132, 93,
            74, 222, 177, 118, 7, 162, 154, 103, 87, 151, 175, 80, 83, 173, 152, 17, 124, 170, 168,
            83, 69, 140, 128, 68,
        ];
        let dataframe = DataFrame::new(buffer);
        let input = String::from_utf8_lossy(dataframe.get_payload().unwrap());

        assert_eq!(input, str);
    }
    #[test]
    fn test_buffer_127_overflow_length() {
        let str = "xZHtBeHbpCWCTCozNw0GxAdQ8Qqqtex5Zje8FBaVQpxrigx92BpLYYiXZnAA70CdNslWvgdSMz0vfUggF8U8wrULZz7ns1tUi5BDWmxx0XS5LsBeyFuaCq4NDAvwbia";
        let buffer: Vec<u8> = vec![
            129, 254, 0, 127, 238, 233, 37, 50, 150, 179, 109, 70, 172, 140, 109, 80, 158, 170,
            114, 113, 186, 170, 74, 72, 160, 158, 21, 117, 150, 168, 65, 99, 214, 184, 84, 67, 154,
            140, 93, 7, 180, 131, 64, 10, 168, 171, 68, 100, 191, 153, 93, 64, 135, 142, 93, 11,
            220, 171, 85, 126, 183, 176, 76, 106, 180, 135, 100, 115, 217, 217, 102, 86, 160, 154,
            73, 101, 152, 142, 65, 97, 163, 147, 21, 68, 136, 188, 66, 85, 168, 209, 112, 10, 153,
            155, 112, 126, 180, 147, 18, 92, 157, 216, 81, 103, 135, 220, 103, 118, 185, 132, 93,
            74, 222, 177, 118, 7, 162, 154, 103, 87, 151, 175, 80, 83, 173, 152, 17, 124, 170, 168,
            83, 69, 140, 128, 68, 0, 0, 0, 0,
        ];
        let dataframe = DataFrame::new(buffer);
        let input = String::from_utf8_lossy(dataframe.get_payload().unwrap());

        assert_eq!(input, str);
    }
    #[test]
    fn test_buffer_large() {
        let str = "asdsadasdasdadsadadasdsadasdasdadsadadasdsadasdasdadsadadasdsadasdasdadsadadasdsadasdasdadsadadasdsadasdasdadsadadasdsadasdasdadsadadasdsadasdasdadsadad";
        let buffer: Vec<u8> = vec![
            129, 254, 0, 152, 156, 22, 133, 192, 253, 101, 225, 179, 253, 114, 228, 179, 248, 119,
            246, 164, 253, 114, 246, 161, 248, 119, 225, 161, 239, 114, 246, 161, 248, 119, 246,
            164, 253, 101, 225, 161, 248, 101, 228, 164, 253, 114, 228, 179, 248, 101, 228, 164,
            253, 101, 225, 161, 239, 114, 228, 164, 239, 119, 225, 161, 248, 119, 246, 164, 239,
            119, 225, 161, 239, 114, 228, 179, 248, 119, 225, 179, 253, 114, 228, 164, 253, 101,
            225, 179, 253, 114, 228, 179, 248, 119, 246, 164, 253, 114, 246, 161, 248, 119, 225,
            161, 239, 114, 246, 161, 248, 119, 246, 164, 253, 101, 225, 161, 248, 101, 228, 164,
            253, 114, 228, 179, 248, 101, 228, 164, 253, 101, 225, 161, 239, 114, 228, 164, 239,
            119, 225, 161, 248, 119, 246, 164, 239, 119, 225, 161, 239, 114, 228, 179, 248, 119,
            225, 179, 253, 114, 228, 164,
        ];
        let dataframe = DataFrame::new(buffer);
        let input = String::from_utf8_lossy(dataframe.get_payload().unwrap());

        assert_eq!(input, str);
    }
    #[test]
    fn test_buffer_overflow_large() {
        let str = "asdsadasdasdadsadadasdsadasdasdadsadadasdsadasdasdadsadadasdsadasdasdadsadadasdsadasdasdadsadadasdsadasdasdadsadadasdsadasdasdadsadadasdsadasdasdadsadad";
        let buffer: Vec<u8> = vec![
            129, 254, 0, 152, 156, 22, 133, 192, 253, 101, 225, 179, 253, 114, 228, 179, 248, 119,
            246, 164, 253, 114, 246, 161, 248, 119, 225, 161, 239, 114, 246, 161, 248, 119, 246,
            164, 253, 101, 225, 161, 248, 101, 228, 164, 253, 114, 228, 179, 248, 101, 228, 164,
            253, 101, 225, 161, 239, 114, 228, 164, 239, 119, 225, 161, 248, 119, 246, 164, 239,
            119, 225, 161, 239, 114, 228, 179, 248, 119, 225, 179, 253, 114, 228, 164, 253, 101,
            225, 179, 253, 114, 228, 179, 248, 119, 246, 164, 253, 114, 246, 161, 248, 119, 225,
            161, 239, 114, 246, 161, 248, 119, 246, 164, 253, 101, 225, 161, 248, 101, 228, 164,
            253, 114, 228, 179, 248, 101, 228, 164, 253, 101, 225, 161, 239, 114, 228, 164, 239,
            119, 225, 161, 248, 119, 246, 164, 239, 119, 225, 161, 239, 114, 228, 179, 248, 119,
            225, 179, 253, 114, 228, 164, 0, 0, 0, 0,
        ];
        let dataframe = DataFrame::new(buffer);
        let input = String::from_utf8_lossy(dataframe.get_payload().unwrap());

        assert_eq!(input, str);
    }
    #[test]
    fn test_mask_data() {
        let masking_key: [u8; 5] = [1, 0, 0, 1, 1];
        let expected_result = vec![128, 254, 5, 1, 153];
        let mut buffer: Vec<u8> = vec![129, 254, 5, 0, 152];
        mask_data(&mut buffer, masking_key);

        assert_eq!(buffer, expected_result);
    }
    #[test]
    fn test_mask_partially_data() {
        let masking_key: [u8; 5] = [1, 0, 0, 1, 1];
        let expected_result = vec![129, 254, 7, 0, 152];
        let mut buffer: Vec<u8> = vec![129, 254, 6, 0, 152];
        mask_data(&mut buffer[2..], masking_key);

        assert_eq!(buffer, expected_result);
    }
    #[test]
    fn test_masking_data_all_zeros() {
        let masking_key: [u8; 5] = [0, 0, 0, 0, 0];
        let expected_result = vec![129, 254, 6, 0, 152];
        let mut buffer: Vec<u8> = vec![129, 254, 6, 0, 152];
        mask_data(&mut buffer, masking_key);

        assert_eq!(buffer, expected_result);
    }
    #[test]
    fn test_masking_data_all_ones() {
        let masking_key: [u8; 5] = [1, 1, 1, 1, 1];
        let expected_result = vec![128, 255, 7, 1, 153];
        let mut buffer: Vec<u8> = vec![129, 254, 6, 0, 152];
        mask_data(&mut buffer, masking_key);

        assert_eq!(buffer, expected_result);
    }
    #[test]
    fn test_mask_partially_data_no_change() {
        let masking_key: [u8; 5] = [0, 0, 0, 1, 1];
        let expected_result = vec![129, 254, 6, 0, 152];
        let mut buffer: Vec<u8> = vec![129, 254, 6, 0, 152];
        mask_data(&mut buffer[2..], masking_key);

        assert_eq!(buffer, expected_result);
    }
    #[cfg(feature = "count-allocations")]
    #[test]
    fn mask_no_allocations() {
        let masking_key: [u8; 5] = [0, 0, 0, 1, 1];
        let mut buffer = vec![129, 254, 6, 0, 152];
        let pt_alloc = allocation_counter::count(|| {
            mask_data(&mut buffer[2..], masking_key);
        });
        assert_eq!(pt_alloc, 0);
    }
}
