#include "X509_certificate_to_der.h"

namespace X509_certificate {

void CertToDER::EncodeBitString(const asn1_types::BitString& bit_string) {
  std::vector<uint8_t> der = types_to_der.EncodeBitString(bit_string);
  der_.insert(der_.end(), der.begin(), der.end());
}

void CertToDER::EncodeInteger(const asn1_types::Integer& integer) {
  std::vector<uint8_t> der = types_to_der.EncodeInteger(integer);
  der_.insert(der_.end(), der.begin(), der.end());
}

void CertToDER::EncodeAlgorithmIdentifier(
    const asn1_types::AlgorithmIdentifier& algorithm_identifier) {
  std::vector<uint8_t> der =
      types_to_der.EncodeAlgorithmIdentifier(algorithm_identifier);
  der_.insert(der_.end(), der.begin(), der.end());
}

void CertToDER::EncodePDU(const asn1_pdu::PDU& pdu) {
  std::vector<uint8_t> der = pdu_to_der.PDUToDER(pdu);
  der_.insert(der_.end(), der.begin(), der.end());
}

template <typename T>
bool CertToDER::UseInvalidField(const T field) {
  return field.has_pdu();
}

void CertToDER::EncodeSequenceIdentifier(
    const asn1_types::Class& sequence_class) {
  // Sequence is encoded with tag number 16 (X690 (2015), 8.9.1).
  // The encoding of a sequence value shall be constructed (X690 (2015), 8.9.1).
  // The class comprises the 7th and 8th bit of the identifier (X.690
  // (2015), 8.1.2).
  der_.push_back((sequence_class << 6) | (1 << 5) | 0x10);
}

void CertToDER::EncodeExtensions(const Extensions& extensions) {
  // |extensions| has class Private (RFC 5280, 4.1 & 4.1.2.8).
  // The pdu does not generate valid extensions. Therefore,
  // need not force the class.
  EncodePDU(extensions.pdu());
}

void CertToDER::EncodeIssuerUniqueId(const IssuerUniqueId& issuer_unique_id) {
  if (UseInvalidField(issuer_unique_id.unique_identifier())) {
    return EncodePDU(issuer_unique_id.unique_identifier().pdu());
  }
  // |issuer_unqiue_id| has class Application (RFC 5280, 4.1 & 4.1.2.8).
  // Preserve the size before insertion in order to later backtrack
  // and explicitly set class to Application.
  size_t size_before_insertion = der_.size();
  EncodeBitString(issuer_unique_id.unique_identifier().bit_string());
  // X.690 (2015), 8.1.2.2: Class Application has value 1.
  der[size_before_insertion] = (der[size_before_insertion] & 0x3F) | (1 << 6));
}

void CertToDER::EncodeSubjectUniqueId(
    const SubjectUniqueId& subject_unique_id) {
  if (UseInvalidField(subject_unique_id.unique_identifier())) {
    return EncodePDU(subject_unique_id.unique_identifier().pdu());
  }
  // |subject_unqiue_id| has class ContextSpecific (RFC 5280, 4.1 & 4.1.2.8).
  // Preserve the size before insertion in order to later backtrack
  // and explicitly set class to ContextSpecific.
  size_t size_before_insertion = der_.size();
  EncodeBitString(subject_unique_id.unique_identifier().bit_string());
  // X.690 (2015), 8.1.2.2: Class ContextSpecific has value 2.
  der[size_before_insertion] = (der[size_before_insertion] & 0x3F) | (2 << 6));
}

void CertToDER::EncodeSubjectPublicKey(
    const SubjectPublicKey& subject_public_key) {
  if (UseInvalidField(subject_public_key)) {
    return EncodePDU(subject_public_key.pdu());
  }
  EncodeBitString(subject_public_key.bit_string());
}

void CertToDER::EncodeSubjectPublicKeyInfo(
    const SubjectPublicKeyInfo& subject_public_key_info) {
  // The fields of |subject_public_key_info| are wrapped around a sequence (RFC
  // 5280, 4.1 & 4.1.2.5).
  EncodeSequenceIdentifier(subject_public_key_info.sequence_class());
  // Save the current size in |len_pos| to place sequence length there
  // after the value is encoded.
  size_t len_pos = der_.size();
  EncodeAlgorithmIdentifier(subject_public_key_info.algorithm_identifier());
  EncodeSubjectPublicKey(subject_public_key_info.subject_public_key());
  // The current size of |der_| subtracted by |len_pos|
  // equates to the size of the value of |subject_public_key_info|.
  der_.insert(der_.begin() + len_pos, der_.size() - len_pos);
}

void CertToDER::EncodeName(const Name& name) {
  EncodePDU(name.pdu());
}

void CertToDER::EncodeSubject(const Subject& subject) {
  EncodeName(subject.name());
}

void CertToDER::EncodeTime(const Time& time) {
  if (UseInvalidField(time)) {
    return EncodePDU(time.pdu());
  }
  std::vector<uint8_t> der;
  // The |Time| field either has an UTCTime or a GeneralizedTime (RFC 5280, 4.1
  // & 4.1.2.5).
  if (time.has_utc_time()) {
    der = types_to_der.EncodeUTCTime(time.utc_time());
  } else {
    der = types_to_der.EncodeGeneralizedTime(time.generalized_time());
  }
  der_.insert(der_.end(), der.begin(), der.end());
}

void CertToDER::EncodeValidity(const Validity& validity) {
  // The fields of |Validity| are wrapped around a sequence (RFC
  // 5280, 4.1 & 4.1.2.5).
  EncodeSequenceIdentifier(validity.sequence_class());
  // Save the current size in |len_pos| to place sequence length there
  // after the value is encoded.
  size_t len_pos = der_.size();
  EncodeTime(validity.not_before().time());
  EncodeTime(validity.not_after().time());
  // The current size of |der_| subtracted by |len_pos|
  // equates to the size of the value of |validity|.
  der_.insert(der_.begin() + len_pos, der_.size() - len_pos);
}

void CertToDER::EncodeIssuer(const Issuer& issuer) {
  EncodeName(issuer.name());
}

void CertToDER::EncodeSignature(const Signature& signature) {
  EncodeAlgorithmIdentifier(signature.algorithm_identifier());
}

void CertToDER::EncodeSerialNumber(const SerialNumber& serial_num) {
  if (UseInvalidField(serial_num)) {
    return EncodePDU(serial_num.pdu());
  }
  EncodeInteger(serial_num.integer());
}

void CertToDER::EncodeVersion(const Version& version) {
  if (UseInvalidField(version)) {
    return EncodePDU(version.pdu());
  }
  // |version| is an integer, so encoded with tag_number 2 (RFC 5280, 4.1
  // & 4.1.2.1).
  // Takes on values 0, 1 and 2, so only require length of 1 to encode it.
  // |version| encoded with universal class (RFC 5280, 4.1 & 4.1.2.1).
  std::vector<uint8_t> der = {0x02, 0x01,
                              static_cast<uint8_t>(version.version_number())};
  der_.insert(der_.end(), der.begin(), der.end());
}

void CertToDER::EncodeTBSCertificate(const TBSCertificate& tbs_certificate) {
  // The fields of |tbs_certificate| are wrapped around a sequence (RFC
  // 5280, 4.1 & 4.1.2.5).
  EncodeSequenceIdentifier(tbs_certificate.sequence_class());
  size_t len_pos = der_.size();

  EncodeVersion(tbs_certificate.version());
  EncodeSerialNumber(tbs_certificate.serial_number());
  EncodeSignature(tbs_certificate.signature());
  EncodeIssuer(tbs_certificate.issuer());
  EncodeValidity(tbs_certificate.validity());
  EncodeSubject(tbs_certificate.subject());
  EncodeSubjectPublicKeyInfo(tbs_certificate.subject_public_key_info());
  // RFC 5280, 4.1: |issuer_unique_id| and |subject_unique_id|
  // are only set for v2 and v3 and |extensions| only set for v3.
  // However, set |issuer_unique_id|, |subject_unique_id|, and |extensions|
  // independently of the version number for interesting inputs.
  if (tbs_certificate.has_issuer_unique_id()) {
    EncodeIssuerUniqueId(tbs_certificate.issuer_unique_id());
  }
  if (tbs_certificate.has_subject_unique_id()) {
    EncodeSubjectUniqueId(tbs_certificate.subject_unique_id());
  }
  if (tbs_certificate.has_extensions()) {
    EncodeExtensions(tbs_certificate.extensions());
  }

  der_.insert(der_.begin() + len_pos, der_.size() - len_pos);
}

void CertToDER::EncodeSignatureAlgorithm(
    const SignatureAlgorithm& signature_algorithm) {
  if (UseInvalidField(signature_algorithm)) {
    return EncodePDU(signature_algorithm.pdu());
  }

  EncodeAlgorithmIdentifier(signature_algorithm.algorithm_identifier());
}

void CertToDER::EncodeSignatureValue(const SignatureValue& signature_value) {
  if (UseInvalidField(signature_value)) {
    return EncodePDU(signature_value.pdu());
  }

  EncodeBitString(signature_value.bit_string());
}

void CertToDER::EncodeX509Certificate(const X509Certificate& X509_certificate) {
  // The fields of |X509_certificate| are wrapped around a sequence (RFC
  // 5280, 4.1 & 4.1.2.5).
  EncodeSequenceIdentifier(X509_certificate.sequence_class());
  // Save the current size in |len_pos| to place sequence length there
  // after the value is encoded.
  size_t len_pos = der_.size();
  EncodeTBSCertificate(X509_certificate.tbs_certificate());
  EncodeSignatureValue(X509_certificate.signature_value());
  // The current size of |der_| subtracted by |len_pos|
  // equates to the size of the value of |X509_certificate|.
  der_.insert(der_.begin() + len_pos, der_.size() - len_pos);
}

std::vector<uint8_t> CertToDER::X509CertificateToDER(
    const X509Certificate& X509_certificate) {
  der_.clear();
  EncodeX509Certificate(X509_certificate);
  return der_;
}

}  // namespace X509_certificate