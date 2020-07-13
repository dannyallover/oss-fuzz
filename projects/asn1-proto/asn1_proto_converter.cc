#include "asn1_proto_converter.h"

namespace asn1_proto {

uint8_t ASN1ProtoConverter::GetNumBytes(size_t num) {
  uint8_t shift = sizeof(size_t);
  while (shift != 0) {
    if (((num >> (shift * 8)) & 0xFF) != 0) {
      return shift;
    }
    shift--;
  }
  return 0;
}

void ASN1ProtoConverter::Append(size_t len, size_t pos) {
  uint8_t len_num_bytes = GetNumBytes(len);
  std::vector<uint8_t> len_vec;
  for (uint8_t i = len_num_bytes; i != 0; i--) {
    len_vec.push_back((len >> (i * 7)) & 0xFF);
  }
  len_vec.push_back((len & 0xFF));
  encoder_.insert(encoder_.begin() + pos, len_vec.begin(), len_vec.end());
}

size_t ASN1ProtoConverter::LongForm(const size_t assigned_len,
                                    const size_t len_pos) {
  uint8_t len_bytes = GetNumBytes(assigned_len);
  if (assigned_len > 127) {
    uint8_t longForm = (1 << 7);
    longForm += len_bytes;
    encoder_.insert(encoder_.begin() + len_pos, longForm);
    return len_bytes;
  }
  return 0;
}

size_t ASN1ProtoConverter::ParseLength(const Length &len,
                                       const size_t actual_len,
                                       const size_t len_pos) {
  size_t assigned_len = 0;
  if (len.has_length_override()) {
    assigned_len = len.length_override().size();
  } else if (len.has_indefinite_form()) {
    assigned_len = 0x80;
    // value is placed before length
    // so the pdu's value is already in encoder
    // we push 0x00 (End-of-Content) for indefinite form
    encoder_.push_back(0x00);
  } else {
    assigned_len = actual_len;
  }
  Append(assigned_len, len_pos);
  size_t long_len_bytes = LongForm(assigned_len, len_pos);
  return GetNumBytes(assigned_len) + long_len_bytes;
}

size_t ASN1ProtoConverter::ParseValue(const Value &val) {
  size_t len;
  if (val.val_array().size() > 0) {
    for (const auto &val_ele : val.val_array()) {
      if (val_ele.has_pdu()) {
        len += ParsePDU(val_ele.pdu());
      } else if (val_ele.has_val_bits() && val_ele.val_bits().size() != 0) {
        len = val_ele.val_bits().size();
        encoder_.insert(encoder_.end(), val_ele.val_bits().begin(),
                        val_ele.val_bits().end());
      } else {
        len = 0;
      }
    }
  }
  return len;
}

size_t ASN1ProtoConverter::HighTagForm(const uint8_t cls, const uint8_t enc,
                                       const uint32_t tag) {
  uint8_t numBytes = GetNumBytes(tag);
  size_t id_parsed = (cls | enc | 0x1F);
  id_parsed <<= 8;
  for (uint8_t i = numBytes; i != 0; i--) {
    id_parsed |= ((0x00 << 7) | ((tag >> (i * 7)) & 0x7F));
    id_parsed <<= 8;
  }
  id_parsed |= ((0x01 << 7) | (tag & 0x7F));
  return id_parsed;
}

size_t ASN1ProtoConverter::ParseIdentifier(const Identifier &id) {
  uint8_t cls = static_cast<uint8_t>(id.cls()) << 6;
  uint8_t enc = static_cast<uint8_t>(id.enc()) << 5;
  uint32_t tag = id.tag();
  size_t id_parsed;
  if (tag <= 31) {
    id_parsed = (cls | enc | tag);
  } else {
    id_parsed = HighTagForm(cls, enc, tag);
  }
  Append(id_parsed, encoder_.size());
  return GetNumBytes(id_parsed);
}

size_t ASN1ProtoConverter::ParsePDU(const PDU &pdu) {
  size_t id_len = ParseIdentifier(pdu.id());
  size_t len_pos = encoder_.size();
  size_t val_len = ParseValue(pdu.val());
  size_t len_len = ParseLength(pdu.len(), id_len + val_len, len_pos);
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
  ParsePDU(pdu);
  ParseToBits();
  return der_.str();
}

}
