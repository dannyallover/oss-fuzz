#include "asn1_proto_converter.h"

namespace asn1_proto {

/* Returns number of bytes needed to encode num
 * Where num is a variable-length integer with
 * no leading zeros
 */
uint8_t ASN1ProtoConverter::GetNumBytes(size_t num) {
  uint8_t shift = sizeof(num);
  while (shift != 0) {
    if (((num >> (shift * 8)) & 0xFF) != 0) {
      return shift;
    }
    shift--;
  }
  return 0;
}

/* Extracts octets from num and inserts
 * them in encoder at the position specified
 */
void ASN1ProtoConverter::AppendBytes(size_t num, size_t pos) {
  uint8_t len_num_bytes = GetNumBytes(num);
  std::vector<uint8_t> len_vec;
  for (uint8_t i = len_num_bytes + 1; i != 0; i--) {
    len_vec.push_back((num >> ((i - 1) * 7)) & 0xFF);
  }
  encoder_.insert(encoder_.begin() + pos, len_vec.begin(), len_vec.end());
}

size_t ASN1ProtoConverter::EncodeLongForm(const size_t assigned_len,
                                          const size_t len_pos) {
  uint8_t len_bytes = GetNumBytes(assigned_len);
  if (assigned_len > 127) {
    uint8_t long_form = (0x80 | len_bytes);
    AppendBytes(long_form, len_pos);
    return len_bytes;
  }
  return 0;
}

/* If Override Length is set, then
 * this function will set the legnth
 * to the abritrary bytes assigned by the proto
 */
size_t ASN1ProtoConverter::EncodeOverrideLength(const std::string len,
                                                const size_t len_pos) {
  size_t assigned_len;
  std::stringstream len_read(len);
  len_read >> assigned_len;
  AppendBytes(assigned_len, len_pos);
  size_t long_len_bytes = EncodeLongForm(assigned_len, len_pos);
  return GetNumBytes(assigned_len) + long_len_bytes;
}

/* If Override Length is not set but
 * Indefinite Form is, then this function
 * will set the length and EOC per the
 * Indefinite Form rules
 */
size_t ASN1ProtoConverter::EncodeIndefiniteLength(const size_t len_pos) {
  AppendBytes(0x80, len_pos);
  // value is placed before length
  // so the pdu's value is already in encoder
  // we push 0x00 0x00 (End-of-Content) for indefinite form
  // which is considered a zero-length object so we
  // need not add anything to the assigned_len
  AppendBytes(0x00, encoder_.size());
  AppendBytes(0x00, encoder_.size());
  return 0x01; // it takes one byte to encode 0x80
}

/* If Override Length and Inefinite Form
 * are not set, then this function will
 * assign the actual length of the pdu
 */
size_t ASN1ProtoConverter::EncodeCorrectLength(const size_t actual_len,
                                               const size_t len_pos) {
  AppendBytes(actual_len, len_pos);
  size_t long_len_bytes = EncodeLongForm(actual_len, len_pos);
  return GetNumBytes(actual_len) + long_len_bytes;
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
  if (val.val_array().size() > 0) {
    for (const auto &val_ele : val.val_array()) {
      if (val_ele.has_pdu()) {
        len += EncodePDU(val_ele.pdu());
      } else {
        len = val_ele.val_bits().size();
        encoder_.insert(encoder_.end(), val_ele.val_bits().begin(),
                        val_ele.val_bits().end());
      }
    }
  }
  return len;
}

size_t ASN1ProtoConverter::EncodeHighTagForm(const uint8_t cls,
                                             const uint8_t enc,
                                             const uint32_t tag) {
  uint8_t numBytes = GetNumBytes(tag);
  size_t id_parsed = (cls | enc | 0x1F);
  id_parsed <<= 8;
  for (uint8_t i = numBytes; i != 0; i--) {
    id_parsed |= ((tag >> (i * 7)) & 0x7F);
    id_parsed <<= 8;
  }
  id_parsed |= ((0x01 << 7) | (tag & 0x7F));
  return id_parsed;
}

size_t ASN1ProtoConverter::EncodeIdentifier(const Identifier &id) {
  uint8_t cls = static_cast<uint8_t>(id.cls()) << 6;
  uint8_t enc = static_cast<uint8_t>(id.enc()) << 5;
  uint32_t tag = id.tag();
  size_t id_parsed;
  if (tag <= 31) {
    id_parsed = (cls | enc | tag);
  } else {
    id_parsed = EncodeHighTagForm(cls, enc, tag);
  }
  AppendBytes(id_parsed, encoder_.size());
  return GetNumBytes(id_parsed);
}

size_t ASN1ProtoConverter::EncodePDU(const PDU &pdu) {
  size_t id_len = EncodeIdentifier(pdu.id());
  size_t len_pos = encoder_.size();
  size_t val_len = EncodeValue(pdu.val());
  size_t len_len = EncodeLength(pdu.len(), id_len + val_len, len_pos);
  return id_len + val_len + len_len;
}

// using this function for checking
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
