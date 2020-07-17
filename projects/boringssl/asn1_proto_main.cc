#include "asn1.pb.h"
#include "asn1_proto_converter.h"
#include "libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h"
#include <openssl/bytestring.h>
#include <openssl/evp.h>
#include <openssl/pkcs8.h>
#include <openssl/x509.h>
#include <iostream>

int FUZZ_HELPER(const uint8_t *buf, size_t len) {
  bssl::UniquePtr<STACK_OF(X509)> certs(sk_X509_new_null());
  EVP_PKEY *key = nullptr;
  CBS cbs;
  CBS_init(&cbs, buf, len);
  PKCS12_get_key_and_certs(&key, certs.get(), &cbs, "foo");
  EVP_PKEY_free(key);
  return 0;
}

void PrintEncodedBits(std::vector<uint8_t> der) {
  for (const uint8_t byte : der) {
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

DEFINE_PROTO_FUZZER(const asn1_proto::PDU &asn1) {
  asn1_proto::ASN1ProtoConverter converter = asn1_proto::ASN1ProtoConverter();
  std::vector<uint8_t> der = converter.ProtoToDER(asn1);
  // PrintEncodedBits(der);
  const uint8_t* ptr = &der[0];
  size_t size = der.size();
  FUZZ_HELPER(ptr, size);
  // for(int i = 0; i < size; i++) {
  //   std::cout << ((*(ptr + i))&0xFF) << " ";
  // }
  // std::cout << std::endl;
  // std::cout << std::endl;
}
