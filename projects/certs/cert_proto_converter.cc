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
    const Signature& signature) {
  std::vector<uint8_t> encoded_signature;
  if(signature.has_invalid_signature()) {
    encoded_signature = pdu2der.PDUToDER(signature.invalid_signature());
  } else {
    encoded_signature = types2der.EncodeBitString(signature.valid_signature());
  }
  
  encoder_.insert(encoder_.end(), encoded_signature.begin(),
                  encoded_signature.end());
}

std::vector<uint8_t> CertProtoConverter::EncodeCertificate(
    const X509Certificate& cert) {
  pdu2der = asn1_pdu::ASN1PDUProtoToDER();
  types2der = asn1_types::ASN1TypesProtoToDER();
  EncodeSignatureValue(cert.signature());
  return encoder_;
}

}  // namespace cert_proto