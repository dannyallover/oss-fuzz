#include "asn1_proto_to_der.h"

namespace asn1_proto {

uint8_t ASN1ProtoToDER::GetNumBytes(const size_t value, const size_t base) {
  uint8_t base_bits = log2(base);
  for (uint8_t num_bits = (sizeof(value) - 1) * 8; num_bits >= base_bits;
       num_bits -= base_bits) {
    if ((value >> num_bits)) {
      return ceil((double)num_bits / base_bits) + 1;
    }
  }
  // Special-case: zero requires one, not zero bytes.
  return 1;
}

void ASN1ProtoToDER::AppendVariableInt(const size_t value, const size_t pos) {
  std::vector<uint8_t> len_vec;
  for (uint8_t shift = GetNumBytes(value, 256); shift != 0; --shift) {
    len_vec.push_back((value >> ((shift - 1) * 8)) & 0xFF);
  }
  encoder_.insert(encoder_.begin() + pos, len_vec.begin(), len_vec.end());
}

size_t ASN1ProtoToDER::EncodeOverrideLength(const std::string raw_len,
                                            const size_t len_pos) {
  encoder_.insert(encoder_.begin() + len_pos, raw_len.begin(), raw_len.end());
  return raw_len.size();
}

size_t ASN1ProtoToDER::EncodeIndefiniteLength(const size_t len_pos) {
  AppendVariableInt(0x80, len_pos);
  // The PDU's value is from |len_pos| to the end of |encoder_|, so just add an
  // EOC marker to the end.
  AppendVariableInt(0x00, encoder_.size());
  AppendVariableInt(0x00, encoder_.size());
  return 3;
}

size_t ASN1ProtoToDER::EncodeDefiniteLength(const size_t actual_len,
                                            const size_t len_pos) {
  AppendVariableInt(actual_len, len_pos);
  size_t len_num_bytes = GetNumBytes(actual_len, 256);
  // X.690 (2015), 8.1.3.3: The long-form is used when the length is
  // larger than 127.
  // Note: |len_num_bytes| is not checked here, because it will return
  // 1 for values [128..255], but those require the long-form length.
  if (actual_len > 127) {
    // See X.690 (2015) 8.1.3.5.
    // Long-form length is encoded as a byte with the high-bit set to indicate
    // the long-form, while the remaining bits indicate how many bytes are used
    // to encode the length.
    AppendVariableInt((0x80 | len_num_bytes), len_pos);
    len_num_bytes += 1;
  }
  return len_num_bytes;
}

size_t ASN1ProtoToDER::EncodeLength(const Length& len,
                                    const size_t actual_len,
                                    const size_t len_pos) {
  if (len.has_length_override()) {
    return EncodeOverrideLength(len.length_override(), len_pos);
  } else if (len.has_indefinite_form() && len.indefinite_form()) {
    return EncodeIndefiniteLength(len_pos);
  } else {
    return EncodeDefiniteLength(actual_len, len_pos);
  }
}

size_t ASN1ProtoToDER::EncodeValue(const Value& val) {
  size_t len = 0;
  for (const auto& val_ele : val.val_array()) {
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

uint8_t ASN1ProtoToDER::EncodeHighTagNumberForm(const uint8_t id_class,
                                                const uint8_t encoding,
                                                const uint32_t tag_num) {
  // The high-tag-number form base 128 encodes |tag_num| (X.690 (2015), 8.1.2).
  uint8_t num_bytes = GetNumBytes(tag_num, 128);
  // High-tag-number form requires the lower 5 bits of the identifier to be set
  // to 1 (X.690 (2015), 8.1.2.4.1).
  uint64_t id_parsed = (id_class | encoding | 0x1F);
  id_parsed <<= 8;
  for (uint8_t i = num_bytes - 1; i != 0; --i) {
    // If it's not the last byte, the high bit is set to 1 (X.690
    // (2015), 8.1.2.4.2).
    id_parsed |= ((0x01 << 7) | ((tag_num >> (i * 7)) & 0x7F));
    id_parsed <<= 8;
  }
  id_parsed |= (tag_num & 0x7F);
  AppendVariableInt(id_parsed, encoder_.size());
  return num_bytes + 1;
}

uint8_t ASN1ProtoToDER::EncodeIdentifier(const Identifier& id) {
  // The class comprises the 7th and 8th bit of the identifier (X.690
  // (2015), 8.1.2).
  uint8_t id_class = static_cast<uint8_t>(id.id_class()) << 6;
  // The encoding comprises the 6th bit of the identifier (X.690 (2015), 8.1.2).
  uint8_t encoding = static_cast<uint8_t>(id.encoding()) << 5;

  uint32_t tag_num = id.tag_num().has_high_tag_num()
                         ? id.tag_num().high_tag_num()
                         : id.tag_num().low_tag_num();
  // When the tag number is greater than or equal to 31, encode with a single
  // byte; otherwise, use the high-tag-number form (X.690 (2015), 8.1.2).
  if (tag_num >= 31) {
    return EncodeHighTagNumberForm(id_class, encoding, tag_num);
  }
  AppendVariableInt((id_class | encoding | tag_num), encoder_.size());
  return 1;  // low-tag-number form requires 1 byte to encode.
}

size_t ASN1ProtoToDER::EncodePDU(const PDU& pdu) {
  ++depth_;
  // Artifically limit the stack depth to avoid stack overflow.
  if (depth_ > 67000) {
    return 0;
  }
  uint8_t id_len = EncodeIdentifier(pdu.id());
  size_t len_pos = encoder_.size();
  size_t val_len = EncodeValue(pdu.val());
  size_t len_len = EncodeLength(pdu.len(), val_len, len_pos);
  --depth_;
  return id_len + val_len + len_len;
}

void ASN1ProtoToDER::PrintEncodedBits() {
  for (const uint8_t byte : encoder_) {
    for (int i = 7; i >= 0; --i) {
      if (((byte >> i) & 0x01)) {
        std::cout << "1";
      } else {
        std::cout << "0";
      }
    }
    std::cout << " ";
  }
}

std::vector<uint8_t> ASN1ProtoToDER::ProtoToDER(const PDU& pdu) {
  EncodePDU(pdu);
  return encoder_;
}

}  // namespace asn1_proto
