#include "asn1_proto_converter.h"

namespace asn1_proto {

// Returns the number of bytes needed to encode |num| into a variable-length
// unsigned integer with no leading zeros.
uint8_t ASN1ProtoConverter::GetNumBytes(const size_t num) {
  uint8_t shift = sizeof(num);
  while (shift != 0) {
    if (((num >> ((shift - 1) * 8)) & 0xFF) != 0) {
      return shift;
    }
    shift--;
  }
  return 0;
}

// Converts |num| to a variable-length, big-endian representation and inserts
// the result into into |encoder_| at |pos|.
void ASN1ProtoConverter::AppendBytes(const size_t num, const size_t pos) {
  uint8_t len_num_bytes = GetNumBytes(num);
  std::vector<uint8_t> len_vec;
  for (uint8_t i = len_num_bytes; i != 0; i--) {
    len_vec.push_back((num >> ((i - 1) * 7)) & 0xFF);
  }
  encoder_.insert(encoder_.begin() + pos, len_vec.begin(), len_vec.end());
}

size_t ASN1ProtoConverter::EncodeLongForm(const size_t assigned_len,
                                          const size_t len_pos) {
  uint8_t len_bytes = GetNumBytes(assigned_len);
  // See X.690 (2015), 8.1.3.5
  // Long-form length is encoded as a byte with the high-bit set to indicate the
  // long-form, while the remaining bits indicate how many bytes are used to
  // encode the length, followed by the actual encoded length.
  AppendBytes((0x80 | len_bytes), len_pos);
  return len_bytes;
}

// If Override Length is set, then this function will set the length to the
// arbitrary bytes assigned by the proto
size_t ASN1ProtoConverter::EncodeOverrideLength(const std::string len,
                                                const size_t len_pos) {
  encoder_.insert(encoder_.begin() + len_pos, len.begin(), len.end());
  return len.size();
}

/* If Override Length is not set but
 * Indefinite Form is, then this function
 * will set the length and EOC per the
 * Indefinite Form rules
 */
size_t ASN1ProtoConverter::EncodeIndefiniteLength(const size_t len_pos) {
  AppendBytes(0x80, len_pos);
  // The value is placed before length, so the pdu's value is already in
  // encoder. We push 0x00 0x00 (End-of-Content) for indefinite form, which is
  // considered a zero-length object so we need not add anything to the
  // assigned_len.
  AppendBytes(0x00, encoder_.size());
  AppendBytes(0x00, encoder_.size());
  return 3; // it takes one byte to encode 0x80
}

/* If Override Length and Inefinite Form
 * are not set, then this function will
 * assign the actual length of the pdu
 */
size_t ASN1ProtoConverter::EncodeCorrectLength(const size_t actual_len,
                                               const size_t len_pos) {
  AppendBytes(actual_len, len_pos);
  size_t len_num_bytes = GetNumBytes(actual_len);
  if (actual_len > 127) {
    return len_num_bytes + EncodeLongForm(actual_len, len_pos);
  }
  return len_num_bytes;
}

size_t ASN1ProtoConverter::EncodeLength(const Length &len,
                                        const size_t actual_len,
                                        const size_t len_pos) {
  if (len.has_length_override()) {
    return EncodeOverrideLength(len.length_override(), len_pos);
  } else if (len.has_indefinite_form() && len.indefinite_form()) {
    return EncodeIndefiniteLength(len_pos);
  } else {
    return EncodeCorrectLength(actual_len, len_pos);
  }
}

size_t ASN1ProtoConverter::EncodeValue(const Value &val) {
  size_t len = 0;
  for (auto it = val.val_array().begin(); it != val.val_array().end(); ++it) {
    if (it->has_pdu()) {
      len += EncodePDU(it->pdu());
    } else {
      len += it->val_bits().size();
      encoder_.insert(encoder_.end(), it->val_bits().begin(),
                      it->val_bits().end());
    }
  }
  return len;
}

uint64_t ASN1ProtoConverter::EncodeHighTagForm(const uint8_t cls,
                                             const uint8_t encoding,
                                             const uint32_t tag) {
  uint8_t numBytes = GetNumBytes(tag);
  // High tag form requires the lower 5 bits to be set to 1.
  uint64_t id_parsed = (cls | encoding | 0x1F);
  id_parsed <<= 8;
  for (uint8_t i = numBytes; i != 0; i--) {
    id_parsed |= ((tag >> (i * 7)) & 0x7F);
    id_parsed <<= 8;
  }
  // The high bit on the last byte is 1.
  id_parsed |= ((0x01 << 7) | (tag & 0x7F));
  return id_parsed;
}

size_t ASN1ProtoConverter::EncodeIdentifier(const Identifier &id) {
  uint8_t cls = static_cast<uint8_t>(id.cls()) << 6;
  uint8_t enc = static_cast<uint8_t>(id.encoding()) << 5;
  uint32_t tag =
      id.tag().has_random_tag() ? id.tag().random_tag() : id.tag().known_tag();
  size_t id_parsed =
      tag <= 31 ? (cls | enc | tag) : EncodeHighTagForm(cls, enc, tag);
  AppendBytes(id_parsed, encoder_.size());
  return GetNumBytes(id_parsed);
}

size_t ASN1ProtoConverter::EncodePDU(const PDU &pdu) {
  size_t id_len = EncodeIdentifier(pdu.id());
  size_t len_pos = encoder_.size();
  size_t val_len = EncodeValue(pdu.val());
  size_t len_len = EncodeLength(pdu.len(), val_len, len_pos);
  return id_len + val_len + len_len;
}

// This function is used for testing and validation.
void ASN1ProtoConverter::ParseToBits() {
  for (const uint8_t byte : encoder_) {
    for (int i = 7; i >= 0; i--) {
      if (((byte >> i) & 0x01)) {
        der_ << "1";
      } else {
        der_ << "0";
      }
    }
    der_ << " ";
  }
}

std::string ASN1ProtoConverter::ProtoToDER(const PDU &pdu) {
  EncodePDU(pdu);
  ParseToBits();
  return der_.str();
}

} // namespace asn1_proto
