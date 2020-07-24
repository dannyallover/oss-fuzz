#include "asn1_primitive_types_to_der.h"

namespace asn1_primitive_types {

uint8_t ASN1PrimitiveTypesToDER::GetNumBytes(const size_t num) {
  for (uint8_t num_bits = sizeof(num) * 8; num_bits > __CHAR_BIT__;
       num_bits -= __CHAR_BIT__) {
    if (num >> num_bits) {
      return ceil((double)num_bits / __CHAR_BIT__);
    }
  }
  // Special-case: zero requires one, not zero bytes.
  return 1;
}

void ASN1PrimitiveTypesToDER::EncodeDefiniteLength(
    const size_t len,
    std::vector<uint8_t>& encoder) {
  encoder.push_back(len);
  // X.690 (2015), 8.1.3.3: The long-form is used when the length is
  // larger than 127.
  // Note: |len_num_bytes| is not checked here, because it will return
  // 1 for values [128..255], but those require the long-form length.
  if (len > 127) {
    // See X.690 (2015) 8.1.3.5.
    // Long-form length is encoded as a byte with the high-bit set to indicate
    // the long-form, while the remaining bits indicate how many bytes are used
    // to encode the length.
    encoder.insert(encoder.begin() + 1, (0x80 | GetNumBytes(len)));
  }
}

void ASN1PrimitiveTypesToDER::EncodeIdentifier(const Identifier& id,
                                               const uint32_t tag,
                                               std::vector<uint8_t>& encoder) {
  // The class comprises the the 7th and 8th bit of the identifier (X.690
  // (2015), 8.1.2).
  uint8_t id_class = static_cast<uint8_t>(id.id_class()) << 6;
  // The encoding, which is the 6th bit, is zero for primitive (X.690
  // (2015), 8.1.2).
  encoder.push_back((id_class | tag));
}

std::vector<uint8_t> ASN1PrimitiveTypesToDER::EncodeBitString(
    const BitString& bit_string) {
  std::vector<uint8_t> encoder;
  EncodeIdentifier(bit_string.id(), 0x03, encoder);
  encoder.push_back(bit_string.val().size() + 1);
  // There are no unused bits.
  // This also acts as EOC if val is empty.
  encoder.push_back(0x00);
  encoder.insert(encoder.end(), bit_string.val().begin(),
                 bit_string.val().end());
  return encoder;
}

std::vector<uint8_t> ASN1PrimitiveTypesToDER::EncodeInteger(
    const Integer& asn1_int) {
  std::vector<uint8_t> encoder;
  EncodeIdentifier(asn1_int.id(), 0x02, encoder);
  encoder.push_back(asn1_int.val().size());
  encoder.insert(encoder.end(), asn1_int.val().begin(), asn1_int.val().end());
  return encoder;
}

std::vector<uint8_t> ASN1PrimitiveTypesToDER::EncodeUTCTime(
    const UTCTime& utc_time) {
  std::vector<uint8_t> encoder;
  EncodeIdentifier(utc_time.id(), 0x17, encoder);
  uint8_t len_pos = encoder.size();
  encoder.push_back(0x30 + utc_time.year_tens_digit());
  encoder.push_back(0x30 + utc_time.year_ones_digit());
  encoder.push_back(0x30 + utc_time.month_tens_digit());
  encoder.push_back(0x30 + utc_time.month_ones_digit());
  encoder.push_back(0x30 + utc_time.day_tens_digit());
  encoder.push_back(0x30 + utc_time.day_ones_digit());
  encoder.push_back(0x30 + utc_time.hour_tens_digit());
  encoder.push_back(0x30 + utc_time.hour_ones_digit());
  encoder.push_back(0x30 + utc_time.minute_tens_digit());
  encoder.push_back(0x30 + utc_time.minute_ones_digit());
  encoder.push_back(0x30 + utc_time.second_tens_digit());
  encoder.push_back(0x30 + utc_time.second_ones_digit());
  if (utc_time.zulu()) {
    encoder.push_back(0x5a);
    encoder.insert(encoder.begin() + len_pos, 13);
  } else {
    encoder.insert(encoder.begin() + len_pos, 12);
  }
  return encoder;
}

}  // namespace asn1_primitive_types