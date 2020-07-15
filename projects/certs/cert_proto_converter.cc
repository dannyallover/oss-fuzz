#include "cert_proto_converter.h"

bool x = false;

namespace cert_proto {

/* Returns number of bytes needed to encode num
 * Where num is a variable-length integer with
 * no leading zeros
 */
uint8_t CertProtoConverter::GetNumBytes(size_t num) {
  uint8_t shift = sizeof(num);
  while (shift != 0) {
    if (((num >> ((shift - 1) * 8)) & 0xFF) != 0) {
      return shift;
    }
    shift--;
  }
  return 0;
}

/* Extracts octets from num and inserts
 * them in encoder at the position specified
 */
void CertProtoConverter::AppendBytes(size_t num, size_t pos) {
  uint8_t len_num_bytes = GetNumBytes(num);
  // std::cout << "the number of bytes for append is" << std::endl;
  // std::cout << (len_num_bytes&0xFFFFFF) << std::endl;
  std::vector<uint8_t> len_vec;
  for (uint8_t i = len_num_bytes; i != 0; i--) {
    // std::cout << "the num pushed back in append is " << std::endl;
    // std::cout << ((num >> ((i - 1) * 7)) & 0xFF) << std::endl;
    len_vec.push_back((num >> ((i - 1) * 7)) & 0xFF);
  }
  encoder_.insert(encoder_.begin() + pos, len_vec.begin(), len_vec.end());
}

size_t CertProtoConverter::EncodeLongForm(const size_t assigned_len,
                                          const size_t len_pos) {
  if (assigned_len > 127) {
    uint8_t len_bytes = GetNumBytes(assigned_len);
    // long form has hight bit set to 1 and lower bits
    // set to number of bytes to encode length
    AppendBytes((0x80 | len_bytes), len_pos);
    return len_bytes;
  }
  return 0;
}

/* If Override Length is set, then
 * this function will set the length
 * to the arbitrary bytes assigned by the proto
 */
size_t CertProtoConverter::EncodeOverrideLength(const std::string len,
                                                const size_t len_pos) {
  encoder_.insert(encoder_.begin() + len_pos, len.begin(), len.end());
  return len.size();
}

/* If Override Length is not set but
 * Indefinite Form is, then this function
 * will set the length and EOC per the
 * Indefinite Form rules
 */
size_t CertProtoConverter::EncodeIndefiniteLength(const size_t len_pos) {
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
size_t CertProtoConverter::EncodeCorrectLength(const size_t actual_len,
                                               const size_t len_pos) {
  // std::cout << "the actual len is " << std::endl;
  // std::cout << (actual_len &0xFFFFFFFF) << std::endl;
  // std::cout << "len_pos is " << std::endl;
  // std::cout << (len_pos &0xFFFFFFFF) << std::endl;
  AppendBytes(actual_len, len_pos);
  size_t long_len_bytes = EncodeLongForm(actual_len, len_pos);
  return GetNumBytes(actual_len) + long_len_bytes;
}

size_t CertProtoConverter::EncodeLength(const Length &len,
                                        const size_t actual_len,
                                        const size_t len_pos) {
  return EncodeCorrectLength(actual_len, len_pos);
}

size_t CertProtoConverter::EncodeValue(const Value &val) {
  size_t len = 0;
  if (val.val_array().size() > 0) {
    for (const auto &val_ele : val.val_array()) {
      // std::cout << "here" << std::endl;
      // std::cout << (encoder_.size() & 0xFFFFFFFFFFF) << std::endl;
      // len = encoder_.size();
      if (val_ele.has_pdu()) {
        size_t temp = EncodePDU(val_ele.pdu());
        std::cout << "HERE IS THE VALUE RETURNED BY THE LENGTH " << std::endl;
        std::cout << (temp&0xFFFFF) << std::endl;
        len += temp;
      } else {
        // len += val_ele.val_bits().size();
        len += 0x01;
        encoder_.push_back(0x01);
        // encoder_.insert(encoder_.end(), val_ele.val_bits().begin(),
        //                 val_ele.val_bits().end());
      }
    }
  } else {
    len = 0x01;
    encoder_.push_back(0x01);
  }
  return len;
}

size_t CertProtoConverter::EncodeHighTagForm(const uint8_t cls,
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

size_t CertProtoConverter::EncodeIdentifier(const Identifier &id) {
  uint8_t cls = static_cast<uint8_t>(id.cls()) << 6;
  uint8_t enc = static_cast<uint8_t>(id.enc()) << 5;
  uint32_t tag = id.tag().valid_tag();
  size_t id_parsed;
  if (tag <= 31) {
    id_parsed = (cls | enc | tag);
    ;
  } else {
    id_parsed = EncodeHighTagForm(cls, enc, tag);
  }
  AppendBytes(id_parsed, encoder_.size());
  return GetNumBytes(id_parsed);
}
// 02 02 01 01

size_t CertProtoConverter::EncodePDU(const PDU &pdu) {
  std::cout << "ENCODE PDU IS CALLED " << std::endl;
  std::cout << "THE SIZE IS " << std::endl;
  std::cout << (pdu.val().val_array().size()&0xFFFF) << std::endl;
  int pduCount = 0;
  int primCount = 0;
  for (const auto &val_ele : pdu.val().val_array()) {
    if (val_ele.has_pdu()) {
      pduCount++;
    } else {
      primCount++;
    }
  }
  std::cout << "THE PDU COUNT IS " << std::endl;
  std::cout << pduCount << std::endl;
  std::cout << "THE PRIM COUNT IS " << std::endl;
  std::cout << primCount << std::endl;

  if(pduCount > 0 && primCount == 0) {
    x = true;
  }

  size_t id_len = EncodeIdentifier(pdu.id());
  std::cout << "the length of id is " << std::endl;
  std::cout << (id_len & 0xFFFFFFFFFFFFFFFF) << std::endl;
  std::cout << "the size of the vector is " << std::endl;
  std::cout << encoder_.size() << std::endl;
  size_t len_pos = encoder_.size();
  size_t val_len = EncodeValue(pdu.val());
  std::cout << "the length of val is " << std::endl;
  std::cout << (val_len & 0xFFFFFFFFFFFFFFFF) << std::endl;
  std::cout << "the length pos " << std::endl;
  std::cout << (len_pos & 0xFFFFFFFFFFFFFFFF) << std::endl;
  std::cout << "the size of the vector is " << std::endl;
  std::cout << encoder_.size() << std::endl;
  size_t len_len = EncodeLength(pdu.len(), val_len, len_pos);
  std::cout << "the length of len is " << std::endl;
  std::cout << (len_len & 0xFFFFFFFFFFFFFFFF) << std::endl;
  std::cout << "the size of the vector is " << std::endl;
  std::cout << encoder_.size() << std::endl;
  std::cout << std::endl;
  std::cout << std::endl;
  return id_len + val_len + len_len;
}

// using this function for checking
void CertProtoConverter::ParseToBits() {
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

std::string CertProtoConverter::EncodeCert(const PDU &pdu) {
  std::cout << "STARTS HERE" << std::endl;
  EncodePDU(pdu);
  if(x && encoder_.size() < 20) {
    ParseToBits();
    std::cout << der_.str() << std::endl;
    exit(0);
  }
  return der_.str();
}

} // namespace cert_proto