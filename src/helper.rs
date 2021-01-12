pub fn get_bit_position(position: u8, bit_length: u8, source: &u16) -> u8 {
    // 1 becomes 1
    // 2 becomes 3
    // 3 necomes 7
    // 4 becomes 15
    // 5 becomes 31
    // Values greater than 8 are possible, for instance its possible to support a value that takes 14 bits
    // Before masking we move the required bits into place
    let translated_position = 16 - (position + bit_length);
    let result = *source >> translated_position;
    debug_assert!(bit_length < 8);
    let length_mask = 2u16.pow(bit_length as u32) - 1;
    // The high bits of this value should always be masked out and be zero since no individual value will have more than 7 bits
    (result & length_mask) as u8
}

pub fn set_bit_position(position: u8, bit_length: u8, data: &mut u16, bits_to_set: u16) {
    // To set bit position 1 with data that is 4 bits long
    // 15 - position
    // 16 - (1 + 4) = 11 meaning we shift left 11 places to place the start of a 4 bit value at position 1
    // To set bit position 11 with data that is 2 bits long
    // 16 - (11 + 2) = 13
    debug_assert!(position < 16);
    debug_assert!(bit_length < 16);
    debug_assert!((position + bit_length) < 16);
    let translated_position = 16 - (position + bit_length);
    let r = bits_to_set << translated_position;
    *data |= r;
}
