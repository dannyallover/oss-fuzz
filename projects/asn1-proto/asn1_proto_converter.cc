#include "asn1_proto_converter.h"
#include <typeinfo>
#include <string>
#include <vector>
#include <cstdint>
#include <stack>
#include <cmath>

#define UNIVERSAL 0b00 << 6
#define APPLICATION 0b10 << 6
#define CONTEXT_SPECIFIC 0b10 << 6
#define PRIVATE 0b11 << 6
#define PRIMITIVE 0b0 << 5
#define CONSTRUCTED 0b1 << 5
#define BYTE_MASK 0xFF

int classes[] = {UNIVERSAL, APPLICATION, CONTEXT_SPECIFIC, PRIVATE};
int encodings[] = {PRIMITIVE, CONSTRUCTED};

namespace asn1_proto {

  uint8_t ASN1ProtoConverter::GetNumBytes(size_t num) {
    int shift = sizeof(size_t);
    while(shift >= 0) {
      if(((num>>(shift*8))&BYTE_MASK) != 0) {
        return shift;
      }
      shift--;
    }
    return 0;
  }

  void ASN1ProtoConverter::Append(size_t len, size_t pos) {
    int len_num_bytes = GetNumBytes(len);
    std::vector<uint8_t> len_vec;
    for(int i = len_num_bytes; i >= 0; i--) {
      len_vec.push_back((len>>(i*7))&BYTE_MASK);
    }
    encoder_.insert(encoder_.begin() + pos, len_vec.begin(), len_vec.end());
  }

  size_t ASN1ProtoConverter::LongForm(const size_t assigned_len, const size_t len_pos) {
    uint8_t len_bytes = GetNumBytes(assigned_len);
    if(assigned_len > 127 || len_bytes > 1) {
      uint8_t longForm = (1 << 7);
      longForm += len_bytes;
      encoder_.insert(encoder_.begin()+len_pos, longForm);
      return len_bytes;
    }
    return 0;
  }

  size_t ASN1ProtoConverter::ParseLength(const Length& len, const size_t actual_len, const size_t len_pos) {
    size_t assigned_len = 0;
    if(len.has_length_override()) {
      assigned_len = len.length_override().size();
    } else {
      assigned_len = actual_len;
    }
    Append(assigned_len, len_pos);
    size_t long_len_bytes = LongForm(assigned_len, len_pos);
    return GetNumBytes(assigned_len) + long_len_bytes;
  }

  size_t ASN1ProtoConverter::ParseValue(const Value& val) {
    size_t len = 0;
    if(val.pdu().size() > 0) {
      for(const PDU pdu : val.pdu()) {
        len += ParsePDU(pdu);
      }
    } else {
      len = val.val().size();
      encoder_.insert(encoder_.end(), val.val().begin(), val.val().end());
    }
    return len;
  }

  size_t ASN1ProtoConverter::HighTagForm(const uint8_t cl, const uint8_t enc, const uint32_t tag) {
    uint8_t numBytes = GetNumBytes(tag);
    size_t id_parsed = (cl | enc | 0b11111);
    for(int i = numBytes; i >= 0; i--) {
      id_parsed <<= 8;
      if(i != 0) {
        id_parsed |= ((0b0 << 7) | ((tag >> (i*7)) & 0x7F));
      } else if(i == 0) {
        id_parsed |= ((0b1 << 7) | ((tag >> (i*7)) & 0x7F));
      }
    }
    return id_parsed;
  }

  size_t ASN1ProtoConverter::ParseIdentifier(const Identifier& id) {
    uint8_t cl = classes[id.cls()];
    uint8_t enc = encodings[id.enc()];
    uint32_t tag = id.tag();
    size_t id_parsed;
    if(tag <= 31) {
      id_parsed = (cl | enc | tag);
    } else {
      id_parsed = HighTagForm(cl, enc, tag);
    }
    Append(id_parsed, encoder_.size());
    return GetNumBytes(id_parsed);
  }

  size_t ASN1ProtoConverter::ParsePDU(const PDU& pdu) {
    size_t id_len = ParseIdentifier(pdu.id());
    size_t len_pos = encoder_.size();
    size_t val_len = ParseValue(pdu.val());
    size_t len_len = ParseLength(pdu.len(), id_len + val_len, len_pos);
    return id_len + val_len;
  }

    // using this function for checking
  void ASN1ProtoConverter::ParseToBits() {
    for(const uint8_t byte : encoder_) {
      for(int i = 7; i>=0; i--) {
        if(((byte >> i) & 0b1) == 1) {
          der_ << "1";
        } else {
          der_ << "0";
        }
      }
      der_ << " ";
    }
  }

  std::string ASN1ProtoConverter::ProtoToDER(const PDU& pdu) {
    ParsePDU(pdu);
    ParseToBits();
    return der_.str();
  }
}
