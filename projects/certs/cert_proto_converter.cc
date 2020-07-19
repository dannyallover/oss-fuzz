#include "cert_proto_converter.h"

namespace cert_proto {

void CertProtoConverter::ParseToBits() {
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

void CertProtoConverter::EncodeSignatureValue(
    const asn1_types::ASN1BitString& bit_string) {
  std::vector<uint8_t> encoded_bit_string =
      types2der.EncodeBitString(bit_string);
  encoder_.insert(encoder_.end(), encoded_bit_string.begin(),
                  encoded_bit_string.end());
}

std::vector<uint8_t> CertProtoConverter::EncodeCertificate(
    const X509Certificate& cert) {
  pdu2der = asn1_pdu::ASN1PDUProtoToDER();
  types2der = asn1_types::ASN1TypesProtoToDER();
  EncodeSignatureValue(cert.signature_value());
  // ParseToBits();
  for (const uint8_t byte : encoder_) {
    std::cout << std::hex << ((byte >> 4)&0xF);
    std::cout << std::hex << (byte&0xF);
    std::cout << " ";
  }
  std::cout << std::endl;
  std::cout << std::endl;
  return encoder_;
}

}  // namespace cert_proto