use crate::InviteError;

pub(crate) const MAX_APPLICATION_ID_BYTES: usize = 64;
pub(crate) const MAX_HOST_BYTES: usize = 253;

pub(crate) struct Decoder<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    pub(crate) fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    pub(crate) fn finish(self) -> Result<(), InviteError> {
        (self.offset == self.input.len())
            .then_some(())
            .ok_or(InviteError::Invalid)
    }

    pub(crate) fn array(&mut self, expected: usize) -> Result<(), InviteError> {
        let length = self.array_len()?;
        (length == expected)
            .then_some(())
            .ok_or(InviteError::Invalid)
    }

    pub(crate) fn array_len(&mut self) -> Result<usize, InviteError> {
        self.length(4)
    }

    pub(crate) fn uint(&mut self) -> Result<u64, InviteError> {
        let byte = self.byte()?;
        if byte >> 5 != 0 {
            return Err(InviteError::Invalid);
        }
        self.additional(byte & 0x1f)
    }

    pub(crate) fn bytes(&mut self, max: usize) -> Result<Vec<u8>, InviteError> {
        let length = self.length(2)?;
        if length > max || self.input.len().saturating_sub(self.offset) < length {
            return Err(InviteError::TooLarge);
        }
        let value = self.input[self.offset..self.offset + length].to_vec();
        self.offset += length;
        Ok(value)
    }

    pub(crate) fn text(&mut self, max: usize) -> Result<String, InviteError> {
        let length = self.length(3)?;
        if length > max || self.input.len().saturating_sub(self.offset) < length {
            return Err(InviteError::TooLarge);
        }
        let value = std::str::from_utf8(&self.input[self.offset..self.offset + length])
            .map_err(|_| InviteError::Invalid)?
            .to_owned();
        self.offset += length;
        Ok(value)
    }

    pub(crate) fn optional_uint(&mut self) -> Result<Option<u64>, InviteError> {
        if self.input.get(self.offset) == Some(&0xf6) {
            self.offset += 1;
            return Ok(None);
        }
        self.uint().map(Some)
    }

    fn length(&mut self, major: u8) -> Result<usize, InviteError> {
        let byte = self.byte()?;
        if byte >> 5 != major {
            return Err(InviteError::Invalid);
        }
        usize::try_from(self.additional(byte & 0x1f)?).map_err(|_| InviteError::TooLarge)
    }

    fn additional(&mut self, additional: u8) -> Result<u64, InviteError> {
        match additional {
            value @ 0..=23 => Ok(value.into()),
            24 => {
                let value = u64::from(self.byte()?);
                (value >= 24).then_some(value).ok_or(InviteError::Invalid)
            }
            25 => {
                let value = u64::from(u16::from_be_bytes(self.take_array()?));
                (value > u8::MAX.into())
                    .then_some(value)
                    .ok_or(InviteError::Invalid)
            }
            26 => {
                let value = u64::from(u32::from_be_bytes(self.take_array()?));
                (value > u16::MAX.into())
                    .then_some(value)
                    .ok_or(InviteError::Invalid)
            }
            27 => {
                let value = u64::from_be_bytes(self.take_array()?);
                (value > u32::MAX.into())
                    .then_some(value)
                    .ok_or(InviteError::Invalid)
            }
            _ => Err(InviteError::Invalid),
        }
    }

    fn byte(&mut self) -> Result<u8, InviteError> {
        let value = *self.input.get(self.offset).ok_or(InviteError::Invalid)?;
        self.offset += 1;
        Ok(value)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], InviteError> {
        if self.input.len().saturating_sub(self.offset) < N {
            return Err(InviteError::Invalid);
        }
        let mut value = [0_u8; N];
        value.copy_from_slice(&self.input[self.offset..self.offset + N]);
        self.offset += N;
        Ok(value)
    }
}

pub(crate) fn encode_array(output: &mut Vec<u8>, length: usize) {
    encode_major(output, 4, length as u64);
}

pub(crate) fn encode_uint(output: &mut Vec<u8>, value: u64) {
    encode_major(output, 0, value);
}

pub(crate) fn encode_bytes(output: &mut Vec<u8>, value: &[u8]) {
    encode_major(output, 2, value.len() as u64);
    output.extend_from_slice(value);
}

pub(crate) fn encode_text(output: &mut Vec<u8>, value: &str) {
    encode_major(output, 3, value.len() as u64);
    output.extend_from_slice(value.as_bytes());
}

pub(crate) fn encode_optional_uint(output: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(value) => encode_uint(output, value),
        None => output.push(0xf6),
    }
}

fn encode_major(output: &mut Vec<u8>, major: u8, value: u64) {
    let prefix = major << 5;
    match value {
        0..=23 => output.push(prefix | value as u8),
        24..=0xff => output.extend_from_slice(&[prefix | 24, value as u8]),
        0x100..=0xffff => {
            output.push(prefix | 25);
            output.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            output.push(prefix | 26);
            output.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            output.push(prefix | 27);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}
