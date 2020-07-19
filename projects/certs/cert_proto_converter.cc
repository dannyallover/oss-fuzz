#include "cert_proto_converter.h"

namespace cert_proto {

uint8_t ASN1ProtoConverter::GetNumBytes(const size_t num) {
  for (uint8_t shift = sizeof(num); shift != 0; --shift) {
    if (((num >> ((shift - 1) * 8)) & 0xFF) != 0) {
      return shift;
    }
  }
  return 1;
}

void ASN1ProtoConverter::AppendBytes(const size_t num, const size_t pos) {
  std::vector<uint8_t> len_vec;
  for (uint8_t shift = GetNumBytes(num); shift != 0; shift--) {
    len_vec.push_back((num >> ((shift - 1) * 8)) & 0xFF);
  }
  encoder_.insert(encoder_.begin() + pos, len_vec.begin(), len_vec.end());
}

size_t ASN1ProtoConverter::EncodeOverrideLength(const std::string raw_len,
                                                const size_t len_pos) {
  encoder_.insert(encoder_.begin() + len_pos, raw_len.begin(), raw_len.end());
  return raw_len.size();
}

size_t ASN1ProtoConverter::EncodeIndefiniteLength(const size_t len_pos) {
  AppendBytes(0x80, len_pos);
  // The PDU's value is from |len_pos| to the end of |encoder_|, so just add an
  // EOC marker to the end.
  AppendBytes(0x00, encoder_.size());
  AppendBytes(0x00, encoder_.size());
  return 3;
}

size_t ASN1ProtoConverter::EncodeCorrectLength(const size_t actual_len,
                                               const size_t len_pos) {
  AppendBytes(actual_len, len_pos);
  size_t len_num_bytes = GetNumBytes(actual_len);
  // X.690 (2015), 8.1.3.3: The long-form is used when the length is
  // larger than 127.
  if (actual_len > 127) {
    // See X.690 (2015) 8.1.3.5.
    // Long-form length is encoded as a byte with the high-bit set to indicate
    // the long-form, while the remaining bits indicate how many bytes are used
    // to encode the length.
    AppendBytes((0x80 | len_num_bytes), len_pos);
    len_num_bytes += 1;
  }
  return len_num_bytes;
}

size_t ASN1ProtoConverter::EncodeLength(const Length& len,
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

size_t ASN1ProtoConverter::EncodeValue(const Value& val) {
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

uint64_t ASN1ProtoConverter::EncodeHighTagForm(const uint8_t id_class,
                                               const uint8_t encoding,
                                               const uint32_t tag) {
  // The high tag form base 128 encodes the tag (X.690 (2015), 8.1.2).
  // Compute number of bytes needed to base 128 encode the high tag.
  uint8_t numBytes = GetNumBytes(tag << GetNumBytes(tag));
  // High tag form requires the lower 5 bits to be set to 1 (X.690
  // (2015), 8.1.2.4.1).
  uint64_t id_parsed = (id_class | encoding | 0x1F);
  id_parsed <<= 8;
  for (uint8_t i = numBytes - 1; i != 0; i--) {
    // If it's not the last byte, the high bit is set to 1 (X.690
    // (2015), 8.1.2.4.2).
    id_parsed |= ((0x01 << 7) | ((tag >> (i * 7)) & 0x7F));
    id_parsed <<= 8;
  }
  id_parsed |= (tag & 0x7F);
  return id_parsed;
}

size_t ASN1ProtoConverter::EncodeIdentifier(const Identifier& id) {
  // The class comprises the the 7th and 8th bit of the identifier (X.690
  // (2015), 8.1.2).
  uint8_t id_class = static_cast<uint8_t>(id.id_class()) << 6;
  // The encoding comprises the 6th bit of the identifier (X.690 (2015), 8.1.2).
  uint8_t encoding = static_cast<uint8_t>(id.encoding()) << 5;

  uint32_t tag =
      id.tag().has_high_tag() ? id.tag().high_tag() : id.tag().low_tag();
  // When the tag is less than 31, encode with a single byte; otherwise,
  // use the high tag form (X.690 (2015), 8.1.2).
  uint64_t id_parsed = tag < 31 ? (id_class | encoding | tag)
                                : EncodeHighTagForm(id_class, encoding, tag);

  AppendBytes(id_parsed, encoder_.size());
  return GetNumBytes(id_parsed);
}

size_t ASN1ProtoConverter::EncodePDU(const PDU& pdu) {
  depth_++;
  // Artifically limit the stack depth to avoid stack overflow.
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

std::vector<uint8_t> ASN1ProtoConverter::ProtoToDER(const PDU& pdu) {
  EncodePDU(pdu);
  return encoder_;
}

}  // namespace cert_proto