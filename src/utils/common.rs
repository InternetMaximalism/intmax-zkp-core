// convert u8 to little endian bits arrary
pub fn to_le_bits(x: u8) -> Vec<bool> {
    let mut x = x;
    let mut r = vec![];
    while x > 0 {
        r.push(x & 1 == 1);
        x >>= 1;
    }

    r.resize(8, false);

    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_le() {
        assert_eq!(
            to_le_bits(1),
            vec![true, false, false, false, false, false, false, false]
        );
        assert_eq!(
            to_le_bits(2),
            vec![false, true, false, false, false, false, false, false]
        );
        assert_eq!(
            to_le_bits(3),
            vec![true, true, false, false, false, false, false, false]
        );
        assert_eq!(
            to_le_bits(8),
            vec![false, false, false, true, false, false, false, false]
        );
    }
}

// pub fn log2_ceil(value: usize) -> u32 {
//     assert!(value != 0, "The first argument must be a positive number.");

//     if value == 1 {
//         return 0;
//     }

//     let mut log_value = 1;
//     let mut tmp_value = value - 1;
//     while tmp_value > 1 {
//         tmp_value /= 2;
//         log_value += 1;
//     }

//     log_value
// }
