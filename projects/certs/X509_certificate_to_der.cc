#include "X509_certificate_to_der.h"

namespace x509_certificate {

void CertToDER::EncodeBitString(const asn1_types::BitString& bit_string) {
  std::vector<uint8_t> der = types_to_der.EncodeBitString(bit_string);
  der_.insert(der_.end(), der.begin(), der.end());
}

void CertToDER::EncodeInteger(const asn1_types::Integer& integer) {
  std::vector<uint8_t> der = types_to_der.EncodeInteger(integer);
  der_.insert(der_.end(), der.begin(), der.end());
}

void CertToDER::EncodeAlgorithmIdentifier(
    const AlgorithmIdentifier& algorithm_identifier) {
  // AlgorithmIdentifier is a sequence (RFC 5280, 4.1.1.2).
  // Sequence is universal, constructed, and encoded with tag number 16 (X.208,
  // Table 1).
  der_.push_back(0x30);
  size_t len = algorithm_identifier.object_identifier().size() +
               algorithm_identifier.parameters().size();
  // EncodeDefiniteLength(len, der);
  der_.insert(der_.end(), algorithm_identifier.object_identifier().begin(),
             algorithm_identifier.object_identifier().end());
  der_.insert(der_.end(), algorithm_identifier.parameters().begin(),
             algorithm_identifier.parameters().end());
}

void CertToDER::EncodePDU(const asn1_pdu::PDU& pdu) {
  std::vector<uint8_t> der = pdu_to_der.PDUToDER(pdu);
  der_.insert(der_.end(), der.begin(), der.end());
}

template <typename T>
bool CertToDER::UseInvalidField(const T field) {
  return field.has_pdu();
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
  // The size before insertion will be the position of the identifier.
  // Preserve to later backtrack and explicitly set class to Application.
  size_t pos_of_identifier = der_.size();
  EncodeBitString(issuer_unique_id.unique_identifier().bit_string());
  // X.690 (2015), 8.1.2.2: Class Application has value 1.
  der_[pos_of_identifier] = ((der_[pos_of_identifier] & 0x3F) | (1 << 6));
}

void CertToDER::EncodeSubjectUniqueId(
    const SubjectUniqueId& subject_unique_id) {
  if (UseInvalidField(subject_unique_id.unique_identifier())) {
    return EncodePDU(subject_unique_id.unique_identifier().pdu());
  }
  // |subject_unqiue_id| has class ContextSpecific (RFC 5280, 4.1 & 4.1.2.8).
  // The size before insertion will be the position of the identifier.
  // Preserve to later backtrack and explicitly set class to ContextSpecific.
  size_t pos_of_identifier = der_.size();
  EncodeBitString(subject_unique_id.unique_identifier().bit_string());
  // X.690 (2015), 8.1.2.2: Class ContextSpecific has value 2.
  der_[pos_of_identifier] = ((der_[pos_of_identifier] & 0x3F) | (2 << 6));
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
  // Sequence is universal, constructed, and encoded with tag number 16 (X.208,
  // Table 1).
  der_.push_back(0x30);
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
  // Sequence is universal, constructed, and encoded with tag number 16 (X.208,
  // Table 1).
  der_.push_back(0x30);
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
  // |version| is an integer, so encoded with tag number 2 (RFC 5280, 4.1
  // & 4.1.2.1).
  // Takes on values 0, 1 and 2, so only require length of 1 to
  // encode it.
  // |version| encoded with universal class (RFC 5280, 4.1 & 4.1.2.1).
  std::vector<uint8_t> der = {0x02, 0x01,
                              static_cast<uint8_t>(version.version_number())};
  der_.insert(der_.end(), der.begin(), der.end());
}

void CertToDER::EncodeTBSCertificate(const TBSCertificate& tbs_certificate) {
  // The fields of |tbs_certificate| are wrapped around a sequence (RFC
  // 5280, 4.1 & 4.1.2.5).
  // Sequence is universal, constructed, and encoded with tag number 16 (X.208,
  // Table 1).
  der_.push_back(0x30);
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
  // Sequence is universal, constructed, and encoded with tag number 16 (X.208,
  // Table 1).
  der_.push_back(0x30);
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