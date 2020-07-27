#ifndef CERT_PROTO_CONVERTER_H_
#define CERT_PROTO_CONVERTER_H_

#include <typeinfo>
#include <vector>

#include "X509_certificate.pb.h"
#include "asn1_pdu_to_der.h"
#include "asn1_types_to_der.h"

namespace X509_certificate {

class CertToDER {
 public:
  // Encodes |X509_certificate| to DER, returning the encoded bytes of the PDU
  // in |der_|.
  std::vector<uint8_t> X509CertificateToDER(
      const X509Certificate& X509_certificate);

 private:
  // Contains encoded X509 Certificate.
  std::vector<uint8_t> der_;

  // Used to encode PDU's for fields that contain them.
  asn1_pdu::ASN1PDUToDER pdu_to_der;

  // Used to encode the ASN1 types that appear in X509 Certificates.
  asn1_types::ASN1TypesToDER types_to_der;

  // Encode(FIELD) properly encodes the field found in X509 Certificates
  // and writes the results to |der_|.
  void EncodeX509Certificate(const X509Certificate& cert);

  void EncodeSignatureValue(const SignatureValue& signature);

  void EncodeSignatureAlgorithm(const SignatureAlgorithm& signature_algorithm);

  void EncodeTBSCertificate(const TBSCertificate& tbs_certificate);

  void EncodeVersion(const Version& version);

  void EncodeSerialNumber(const SerialNumber& serial_num);

  void EncodeSignature(const Signature& signature);

  void EncodeIssuer(const Issuer& issuer);

  void EncodeValidity(const Validity& validity);

  void EncodeTime(const Time& time);

  void EncodeSubject(const Subject& subject);

  void EncodeName(const Name& name);

  void EncodeSubjectPublicKeyInfo(
      const SubjectPublicKeyInfo& subject_public_key_info);

  void EncodeSubjectPublicKey(const SubjectPublicKey& subject_public_key);

  void EncodeIssuerUniqueId(const IssuerUniqueId& issuer_unique_id);

  void EncodeSubjectUniqueId(const SubjectUniqueId& subject_unique_id);

  void EncodeExtensions(const Extensions& extensions);

  // Encodes |bit_string| through |types_to_der|'s API |EncodeBitString|
  // and writes the results to |der_|.
  void EncodeBitString(const asn1_types::BitString& bit_string);

  // Encodes |integer| through |types_to_der|'s API |EncodeInteger|
  // and writes the results to |der_|.
  void EncodeInteger(const asn1_types::Integer& integer);

  // Encodes |algorithm_identifier| through |types_to_der|'s API
  // |EncodeAlgorithmIdentifier| and writes the results to |der_|.
  void EncodeAlgorithmIdentifier(
      const asn1_types::AlgorithmIdentifier& algorithm_identifier);

  // Encodes |pdu| through |pdu_to_der|'s API EncodePDU
  // and writes the results to |der_|.
  void EncodePDU(const asn1_pdu::PDU& pdu);

  // X509 Certificate fields have a pdu which is used to
  // encode arbitrary TLV's for that field.
  // Checks if |field| contains pdu to encode.
  template <typename T>
  bool UseInvalidField(const T field);

  // X509 Certificates and its counterparts encapsulate
  // a sequence of fields (RFC 5280, 4.1.1).
  // Encodes the tag of a sequence with setting the class to |sequence_class|.
  void EncodeSequenceIdentifier(const asn1_types::Class& sequence_class);
};

}  // namespace X509_certificate

#endif