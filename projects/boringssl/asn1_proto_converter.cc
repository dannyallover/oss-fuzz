#include "asn1_proto_converter.h"

namespace asn1_proto {

// Returns the number of bytes needed to encode |num| into a variable-length
// unsigned integer with no leading zeros.
uint8_t ASN1ProtoConverter::GetNumBytes(const size_t num) {
  for (uint8_t shift = sizeof(num); shift != 0; --shift) {
    if (((num >> ((shift - 1) * 8)) & 0xFF) != 0) {
      return shift;
    }
  }
  return 0;
}

// Converts |num| to a variable-length, big-endian representation and inserts
// the result into into |encoder_| at |pos|.
void ASN1ProtoConverter::AppendBytes(const size_t num, const size_t pos) {
  std::vector<uint8_t> len_vec;
  for (uint8_t shift = GetNumBytes(num); shift != 0; shift--) {
    len_vec.push_back((num >> ((shift - 1) * 8)) & 0xFF);
  }
  if (len_vec.size() == 0) {
    len_vec.push_back(0x00);
  }
  encoder_.insert(encoder_.begin() + pos, len_vec.begin(), len_vec.end());
}

size_t ASN1ProtoConverter::EncodeLongForm(const size_t assigned_len,
                                          const size_t len_pos) {
  uint8_t len_bytes = GetNumBytes(assigned_len);
  // Long-form length is encoded as a byte with the high-bit set to indicate the
  // long-form, while the remaining bits indicate how many bytes are used to
  // encode the length (X.690, 2015, 8.1.3.5).
  AppendBytes((0x80 | len_bytes), len_pos);
  return len_bytes;
}

// If Override Length is set, then this function will set the length to the
// arbitrary bytes assigned by the proto.
size_t ASN1ProtoConverter::EncodeOverrideLength(const std::string len,
                                                const size_t len_pos) {
  encoder_.insert(encoder_.begin() + len_pos, len.begin(), len.end());
  return len.size();
}

// If Override Length is not set but, Indefinite Form is, then this function
// will set the length and EOC per the Indefinite Form rules (X.690,
// 2015, 8.1.3.6).
size_t ASN1ProtoConverter::EncodeIndefiniteLength(const size_t len_pos) {
  AppendBytes(0x80, len_pos);
  // The value is placed before length, so the pdu's value is already in
  // |encoder_|, so we push EOC to the end of |encoder_|.
  AppendBytes(0x00, encoder_.size());
  AppendBytes(0x00, encoder_.size());
  return 3;
}

// If Override Length and Inefinite Form are not set, then this function will
// assign the actual length of the pdu according to DER definite-form (X.690,
// 2015, 8.1.3-8.1.5 & 10.1).
size_t ASN1ProtoConverter::EncodeCorrectLength(const size_t actual_len,
                                               const size_t len_pos) {
  if (actual_len == 0) {
    encoder_.push_back(0x00); // end of contents
    return 1;
  }
  AppendBytes(actual_len, len_pos);
  size_t len_num_bytes = GetNumBytes(actual_len);
  // The long-form is used when the length is larger than 127 (X.690,
  // 2015, 8.1.3.3).
  if (actual_len > 127) {
    return len_num_bytes + EncodeLongForm(actual_len, len_pos);
  }
  return len_num_bytes;
}

size_t ASN1ProtoConverter::EncodeLength(const Length &len,
                                        const size_t actual_len,
                                        const size_t len_pos) {
  // if (len.has_length_override()) {
  //   return EncodeOverrideLength(len.length_override(), len_pos);
  // } else if (len.has_indefinite_form() && len.indefinite_form()) {
  //   return EncodeIndefiniteLength(len_pos);
  // } else {
  //   return EncodeCorrectLength(actual_len, len_pos);
  // }
  return EncodeCorrectLength(actual_len, len_pos);
}

size_t ASN1ProtoConverter::EncodeValue(const Value &val) {
  int count = 0;
  int pduCount = 0;
  int primCount = 0;
  for (const auto &val_ele : val.val_array()) {
    if (val_ele.has_pdu()) {
      pduCount++;
    } else {
      primCount++;
    }
  }
  types += pduCount;
  size_t len = 0;
  for (const auto &val_ele : val.val_array()) {
    if (val_ele.has_pdu()) {
      len += EncodePDU(val_ele.pdu());
    } else {
      len += val_ele.val_bits().size();
      encoder_.insert(encoder_.end(), val_ele.val_bits().begin(),
                      val_ele.val_bits().end());
    }
  }
  return len;
}

uint64_t ASN1ProtoConverter::EncodeHighTagForm(const uint8_t id_class,
                                               const uint8_t encoding,
                                               const uint32_t tag) {
  // High tag form requires the lower 5 bits to be set to 1 (X.690,
  // 2015, 8.1.2.4.1).
  uint64_t id_parsed = (id_class | encoding | 0x1F);
  id_parsed <<= 8;
  for (uint8_t i = GetNumBytes(tag << GetNumBytes(tag)) - 1; i != 0; i--) {
    id_parsed |= ((0x01 << 7) | ((tag >> (i * 7)) & 0x7F));
    id_parsed <<= 8;
  }
  // The high bit on the last byte is set to 1 (X.690, 2015, 8.1.2.4.2).
  id_parsed |= ((0x00 << 7) | (tag & 0x7F));
  return id_parsed;
}

size_t ASN1ProtoConverter::EncodeIdentifier(const Identifier &id) {
  // The class comprises the the 7th and 8th bit of the identifier (X.690,
  // 2015, 8.1.2).
  uint8_t id_class = static_cast<uint8_t>(id.id_class()) << 6;
  // The encoding comprises the 6th bit of the identifier (X.690, 2015, 8.1.2).
  uint8_t encoding = static_cast<uint8_t>(id.encoding()) << 5;

  uint32_t tag =
      id.tag().has_high_tag() ? id.tag().high_tag() : id.tag().low_tag();
  if(tag == 0) {
    tag = 0x01;
  }


  // When the tag is less than 31, we encode with a single byte; otherwise,
  // we use the high tag form (X.690, 2015, 8.1.2).
  uint64_t id_parsed = tag < 31 ? (id_class | encoding | tag)
                                : EncodeHighTagForm(id_class, encoding, tag);

  AppendBytes(id_parsed, encoder_.size());
  if (GetNumBytes(id_parsed) == 0)
    return 1;
  return GetNumBytes(id_parsed);
}

size_t ASN1ProtoConverter::EncodePDU(const PDU &pdu) {
  depth_++;
  // We artifically limit the stack depth to avoid stack overflow.
  if (depth_ > 67000) {
    return 0;
  }

  size_t id_len = EncodeIdentifier(pdu.id());
  size_t len_pos = encoder_.size();
  size_t val_len = EncodeValue(pdu.val());
  size_t len_len = EncodeLength(pdu.len(), val_len, len_pos);
  depth_--;
  return id_len + val_len + len_len;
}

// This function is used for testing and validation.
void ASN1ProtoConverter::ParseToBits() {
  for (const uint8_t byte : encoder_) {
    for (int i = 7; i >= 0; i--) {
      if (((byte >> i) & 0x01)) {
        std::cout << "1";
      } else {
        std::cout << "0";
      }
    }
    std::cout << " ";
  }
}

std::vector<uint8_t> ASN1ProtoConverter::ProtoToDER(const PDU &pdu) {
  EncodePDU(pdu);
  return encoder_;
}

} // namespace asn1_proto
