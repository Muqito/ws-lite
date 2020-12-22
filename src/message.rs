#[derive(Debug)]
pub enum Message {
    Text(String),
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close,
}
impl Message {
    pub fn is_closed(&self) -> bool {
        matches!(self, Message::Close)
    }
}
impl AsRef<[u8]> for Message {
    fn as_ref(&self) -> &[u8] {
        match self {
            Message::Text(x) => x.as_bytes(),
            Message::Binary(x) => x.as_slice(),
            Message::Ping(x) => x.as_slice(),
            Message::Pong(x) => x.as_slice(),
            Message::Close => [136, 3, 98, 121, 101].as_slice(),
        }
    }
}
pub struct WriteMessage {
    output: Vec<u8>,
}

impl WriteMessage {
    pub fn new<D>(input: D) -> WriteMessage
    where
        D: AsRef<[u8]>,
    {
        WriteMessage {
            output: message_to_tcp_write_data(D::as_ref(&input)),
        }
    }
    pub fn get_output(&self) -> &Vec<u8> {
        &self.output
    }
}
impl AsRef<[u8]> for WriteMessage {
    fn as_ref(&self) -> &[u8] {
        self.get_output().as_slice()
    }
}
fn message_to_tcp_write_data<D>(data: D) -> Vec<u8>
where
    D: AsRef<[u8]>,
{
    let data = D::as_ref(&data);
    let mut buffer: Vec<u8> = Vec::with_capacity(data.len() + 10);
    buffer.push(129);

    match data.len() as u64 {
        size @ 0..=125 => {
            buffer.push(size as u8);
        }
        size if size <= u32::MAX as u64 => {
            let new_bytes: [u8; 2] = (size as u16).to_be_bytes();

            buffer.push(126);
            buffer.extend_from_slice(&new_bytes);
        }
        size if size > u32::MAX as u64 => {
            let new_bytes: [u8; 8] = (size as u64).to_be_bytes();

            buffer.push(127);
            buffer.extend_from_slice(&new_bytes);
        }
        _ => panic!("Don't know what to do here..."),
    };

    buffer.extend_from_slice(data);

    buffer
}

impl From<Message> for WriteMessage {
    fn from(message: Message) -> Self {
        WriteMessage::new(message.as_ref())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_close_frame() {
        let expected_result = [136, 3, 98, 121, 101];
        let message = Message::Close;
        let result = message.as_ref();
        assert_eq!(result, expected_result);
    }
}
