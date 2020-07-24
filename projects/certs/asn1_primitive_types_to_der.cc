#include "asn1_primitive_types_to_der.h"

namespace asn1_primitive_types {

uint8_t ASN1TypesProtoToDER::GetNumBytes(const size_t num) {
  for (uint8_t num_bits = sizeof(num) * 8; num_bits > __CHAR_BIT__;
       num_bits -= __CHAR_BIT__) {
    if (num >> num_bits) {
      return ceil((double)num_bits / __CHAR_BIT__);
    }
  }
  // Special-case: zero requires one, not zero bytes.
  return 1;
}

void ASN1TypesProtoToDER::EncodeDefiniteLength(const size_t len, std::vector<uint8_t>& encoder_) {
  encoder_.push_back(len);
  // X.690 (2015), 8.1.3.3: The long-form is used when the length is
  // larger than 127.
  // Note: |len_num_bytes| is not checked here, because it will return
  // 1 for values [128..255], but those require the long-form length.
  if (len > 127) {
    // See X.690 (2015) 8.1.3.5.
    // Long-form length is encoded as a byte with the high-bit set to indicate
    // the long-form, while the remaining bits indicate how many bytes are used
    // to encode the length.
    encoder_.insert(encoder_.begin() + 1, (0x80 | GetNumBytes(len)));
  }
}

void ASN1TypesProtoToDER::EncodeIdentifier(const Identifier& id,
                                           const uint32_t tag,
                                           std::vector<uint8_t>& encoder_) {
  // The class comprises the the 7th and 8th bit of the identifier (X.690
  // (2015), 8.1.2).
  uint8_t id_class = static_cast<uint8_t>(id.id_class()) << 6;
  // The encoding comprises the 6th bit of the identifier (X.690 (2015), 8.1.2).
  uint8_t encoding = static_cast<uint8_t>(id.encoding()) << 5;
  encoder_.push_back((id_class | encoding | tag));
}

std::vector<uint8_t> ASN1TypesProtoToDER::EncodeBitString(
    const BitString& bit_string) {
  std::vector<uint8_t> encoder_;
  EncodeIdentifier(bit_string.id(), 0x03, encoder_);
  encoder_.push_back(bit_string.val().size() + 1);
  // There are no unused bits.
  // This also acts as EOC if val is empty.
  encoder_.push_back(0x00);
  encoder_.insert(encoder_.end(), bit_string.val().begin(),
                  bit_string.val().end());
  return encoder_;
}

std::vector<uint8_t> ASN1TypesProtoToDER::EncodeInteger(
    const Integer& asn1_int) {
  std::vector<uint8_t> encoder_;
  EncodeIdentifier(asn1_int.id(), 0x02, encoder_);
  encoder_.push_back(asn1_int.val().size());
  encoder_.insert(encoder_.end(), asn1_int.val().begin(), asn1_int.val().end());
  return encoder_;
}

}  // namespace asn1_types