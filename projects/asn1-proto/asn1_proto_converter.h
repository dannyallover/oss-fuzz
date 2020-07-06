#ifndef ASN1_PROTO_CONVERTER_H_
#define ASN1_PROTO_CONVERTER_H_

#include <sstream>
#include <string>
#include <iostream>
#include <stack>

#include "asn1.pb.h"

namespace asn1_proto {
  class ASN1ProtoConverter {
   public:
    std::string ProtoToDER(const ASN1Object& asn1Obj);

   private:
    std::stringstream der_;
    std::vector<uint8_t> encoder;

    void ParseToHex(std::vector<uint8_t> encoder);
    std::vector<uint8_t> ParseObject(const ASN1Object& asn1Obj);
    std::vector<uint8_t> ParseSequence(const ASN1Seq& asn1Seq);
    std::vector<uint8_t> ParseInt(const ASN1Integer& asn1Int);
    std::vector<uint8_t> ParseNull(const ASN1Null& asn1Null);
    std::vector<uint8_t> AppendLength(std::vector<uint8_t> len, int lenPos);
    std::vector<uint8_t> AddNums(std::vector<uint8_t> len1, std::vector<uint8_t> len2);
    std::vector<uint8_t> NumToVector(uint64_t len);
    std::vector<uint8_t> ParseBool(const ASN1Boolean& asn1Bool);
    std::vector<uint8_t> ParsePrimitive(const ASN1Primitive& asn1Primitive);
    std::vector<uint8_t> ParseConstructive(const ASN1Constructive& asn1Constructive);
    std::vector<uint8_t> ParseString(const ASN1String& asn1Str);
    std::vector<uint8_t> ParsePrintableString(const ASN1PrintableString& asn1PS);
    std::vector<uint8_t> ParseIA5String(const ASN1IA5String& asn1IA5);
    std::vector<uint8_t> ParseSequenceOf(const ASN1SeqOf& asn1SeqOf);
  };
}

#endif
