#include "asn1_proto_converter.h"
#include <typeinfo>
#include <string>
#include <vector>
#include <cstdint>
#include <stack>
#include <cmath>

#define SEQUENCE_TAG 0x30
#define SEQUENCE_OF_TAG 0x30
#define INT_TAG 0x02
#define NULL_TAG 0x05
#define IA5_STRING_TAG 0x16
#define PRINTABLE_STRING_TAG 0x13
#define BOOL_TAG 0x01
#define OFFSET 0x02
#define NULL_VALUE 0x00
#define DEFAULT_VALUE 0x01
#define DEFAULT_SIZE 0x01
#define BYTE_MASK 0xFF
#define NIBBLE_MASK 0xF

namespace asn1_proto {

  std::vector<uint8_t> ASN1ProtoConverter::NumToVector(uint64_t len) {
    std::vector<uint8_t> num;
    int shift = 7;
    while(shift >= 0) {
      if(((len>>(shift*8))&BYTE_MASK) == 0) {
        shift--;
      } else {
        break;
      }
    }
    for(int i = shift; i >= 0; i--) {
      num.push_back(((len>>(i*8))&BYTE_MASK));
    }
    return num;
  }

  std::vector<uint8_t> ASN1ProtoConverter::AddNums(std::vector<uint8_t> len1, std::vector<uint8_t> len2) {
    if(len1.size() > len2.size()) {
      len1.swap(len2);
    }

    std::vector<uint8_t> sum;

    int size1 = len1.size();
    int size2 = len2.size();
    int diff = size2 - size1;

    uint16_t carry = 0;

    for(int i=size1-1; i>= 0; i--) {
      uint16_t num = len1[i] + len2[i+diff] + carry;
      sum.push_back(num%0x100);
      carry = (num/0x100);
    }

    for(int i = size2-size1-1; i>=0; i--) {
      uint16_t num = len2[i] + carry;
      sum.push_back(num%0x100);
      carry = (num/0x100);
    }

    if(carry) {
      sum.push_back(carry);
    }

    reverse(sum.begin(), sum.end());

    return sum;
  }

  std::vector<uint8_t> ASN1ProtoConverter::AppendLength(std::vector<uint8_t> len, int lenPos) {
    encoder.insert(encoder.begin()+lenPos, len.begin(), len.end());
    if(len.size() == 0) {
      encoder.insert(encoder.begin()+lenPos, 0x00);
    } else if(len.size() > 1 || (len[0]&BYTE_MASK) > 127) {
      uint8_t extra = len.size();
      uint8_t longForm = (1 << 7);
      longForm += extra;
      encoder.insert(encoder.begin()+lenPos, longForm);
      len = AddNums(len, NumToVector(extra));
    }
    return AddNums(len, NumToVector(OFFSET));
  }

  std::vector<uint8_t> ASN1ProtoConverter::ParseNull(const ASN1Null& asn1Null) {
    encoder.push_back(NULL_TAG);
    encoder.push_back(NULL_VALUE);
    return {OFFSET};
  }

  std::vector<uint8_t> ASN1ProtoConverter::ParseBool(const ASN1Boolean& asn1Bool) {
    encoder.push_back(BOOL_TAG);
    std::vector<uint8_t> len = AppendLength(NumToVector(DEFAULT_SIZE), encoder.size());
    encoder.push_back(asn1Bool.val());
    return len;
  }

  std::vector<uint8_t> ASN1ProtoConverter::ParseInt(const ASN1Integer& asn1Int) {
    encoder.push_back(INT_TAG);
    std::string val = asn1Int.val().data();
    std::vector<uint8_t> len;
    if(val.begin() != val.end()) {
      len = AppendLength(NumToVector(val.size()), encoder.size());
      encoder.insert(encoder.end(), val.begin(), val.end());
    } else {
      len = AppendLength(NumToVector(DEFAULT_SIZE), encoder.size());
      encoder.push_back(DEFAULT_VALUE);
    }
    return len;
  }

  std::vector<uint8_t> ASN1ProtoConverter::ParseIA5String(const ASN1IA5String& asn1IA5) {
    encoder.push_back(IA5_STRING_TAG);
    std::string str = asn1IA5.asn1_ia5();
    std::vector<uint8_t> len = AppendLength(NumToVector(str.size()), encoder.size());
    encoder.insert(encoder.end(), str.begin(), str.end());
    return len;
  }

  std::vector<uint8_t> ASN1ProtoConverter::ParsePrintableString(const ASN1PrintableString& asn1PS) {
    encoder.push_back(PRINTABLE_STRING_TAG);
    std::string str = asn1PS.asn1_ps();
    std::vector<uint8_t> len = AppendLength(NumToVector(str.size()), encoder.size());
    encoder.insert(encoder.end(), str.begin(), str.end());
    return len;
  }

  std::vector<uint8_t> ASN1ProtoConverter::ParseString(const ASN1String& asn1Str) {
    if(asn1Str.has_asn1_ps()) {
      return ParsePrintableString(asn1Str.asn1_ps());
    } else if(asn1Str.has_asn1_ia5()) {
      return ParseIA5String(asn1Str.asn1_ia5());
    } else {
      return ParseNull(asn1Str.asn1_null());
    }
  }

  std::vector<uint8_t> ASN1ProtoConverter::ParseSequenceOf(const ASN1SeqOf& asn1SeqOf) {
    encoder.push_back(SEQUENCE_OF_TAG);
    int lenPos = encoder.size();
    std::vector<uint8_t> len;
    for(int i = 0; i < (uint8_t)asn1SeqOf.rep_value(); i++) {
      len = AddNums(len, ParseObject(asn1SeqOf.asn1_obj()));
    }
    return AppendLength(len, lenPos);
  }

  std::vector<uint8_t> ASN1ProtoConverter::ParseSequence(const ASN1Seq& asn1Seq) {
    encoder.push_back(SEQUENCE_TAG);
    int lenPos = encoder.size();
    std::vector<uint8_t> len;
    for(const auto asn1Obj : asn1Seq.asn1_obj()) {
      len = AddNums(len, ParseObject(asn1Obj));
    }
    return AppendLength(len, lenPos);
  }

  std::vector<uint8_t> ASN1ProtoConverter::ParsePrimitive(const ASN1Primitive& asn1Primitive) {
    if(asn1Primitive.has_asn1_int()) {
      return ParseInt(asn1Primitive.asn1_int());
    } else if(asn1Primitive.has_asn1_bool()){
      return ParseBool(asn1Primitive.asn1_bool());
    } else if(asn1Primitive.has_asn1_str()) {
      return ParseString(asn1Primitive.asn1_str());
    } else {
      return ParseNull(asn1Primitive.asn1_null());
    }
  }

  std::vector<uint8_t> ASN1ProtoConverter::ParseConstructive(const ASN1Constructive& asn1Constructive) {
    if(asn1Constructive.has_asn1_seq()) {
      return ParseSequence(asn1Constructive.asn1_seq());
    } else if(asn1Constructive.has_asn1_seq_of()) {
      return ParseSequenceOf(asn1Constructive.asn1_seq_of());
    }else {
      return ParseNull(asn1Constructive.asn1_null());
    }
  }

  std::vector<uint8_t> ASN1ProtoConverter::ParseObject(const ASN1Object& asn1Obj) {
    if(asn1Obj.has_asn1_constructive()) {
      return ParseConstructive(asn1Obj.asn1_constructive());
    } else if(asn1Obj.has_asn1_primitive()) {
      return ParsePrimitive(asn1Obj.asn1_primitive());
    } else {
      return ParseNull(asn1Obj.asn1_null());
    }
  }

  void ASN1ProtoConverter::ParseToHex(std::vector<uint8_t> encoder) {
    for(const uint8_t byte : encoder) {
      der_ << std::hex << ((byte >> 4) & NIBBLE_MASK);
      der_ << std::hex << (byte & NIBBLE_MASK);
      der_ << " ";
    }
  }

  std::string ASN1ProtoConverter::ProtoToDER(const ASN1Object& asn1Obj) {
    ParseObject(asn1Obj);
    ParseToHex(encoder);
    return der_.str();
  }

}
