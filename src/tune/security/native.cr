require "openssl"

@[Link("crypto")]
lib TuneCrypto
  alias Handle = Void*
  fun EVP_PKEY_CTX_new_from_name(Handle, UInt8*, UInt8*) : Handle
  fun EVP_PKEY_keygen_init(Handle) : Int32
  fun EVP_PKEY_CTX_set_rsa_keygen_bits(Handle, Int32) : Int32
  fun EVP_PKEY_keygen(Handle, Handle*) : Int32
  fun EVP_PKEY_CTX_free(Handle)
  fun EVP_PKEY_free(Handle)
  fun EVP_PKEY_new_raw_private_key_ex(Handle, UInt8*, UInt8*, UInt8*, LibC::SizeT) : Handle
  fun EVP_PKEY_new_raw_public_key_ex(Handle, UInt8*, UInt8*, UInt8*, LibC::SizeT) : Handle
  fun EVP_PKEY_get_raw_private_key(Handle, UInt8*, LibC::SizeT*) : Int32
  fun EVP_PKEY_get_raw_public_key(Handle, UInt8*, LibC::SizeT*) : Int32
  fun EVP_MD_CTX_new : LibCrypto::EVP_MD_CTX
  fun EVP_MD_CTX_free(LibCrypto::EVP_MD_CTX)
  fun EVP_sha256 : LibCrypto::EVP_MD
  fun EVP_DigestSignInit(LibCrypto::EVP_MD_CTX, Handle*, LibCrypto::EVP_MD, Handle, Handle) : Int32
  fun EVP_DigestSign(LibCrypto::EVP_MD_CTX, UInt8*, LibC::SizeT*, UInt8*, LibC::SizeT) : Int32
  fun EVP_DigestVerifyInit(LibCrypto::EVP_MD_CTX, Handle*, LibCrypto::EVP_MD, Handle, Handle) : Int32
  fun EVP_DigestVerify(LibCrypto::EVP_MD_CTX, UInt8*, LibC::SizeT, UInt8*, LibC::SizeT) : Int32
  fun BIO_s_mem : LibCrypto::BioMethod*
  fun BIO_new(LibCrypto::BioMethod*) : LibCrypto::Bio*
  fun BIO_new_mem_buf(UInt8*, Int32) : LibCrypto::Bio*
  fun BIO_free(LibCrypto::Bio*) : Int32
  fun BIO_ctrl_pending(LibCrypto::Bio*) : LibC::SizeT
  fun BIO_read(LibCrypto::Bio*, UInt8*, Int32) : Int32
  fun PEM_write_bio_PrivateKey(LibCrypto::Bio*, Handle, Handle, UInt8*, Int32, Handle, Handle) : Int32
  fun PEM_read_bio_PrivateKey(LibCrypto::Bio*, Handle*, Handle, Handle) : Handle
  fun EVP_PKEY_get_bn_param(Handle, UInt8*, Handle*) : Int32
  fun BN_num_bits(Handle) : Int32
  fun BN_bn2bin(Handle, UInt8*) : Int32
  fun BN_free(Handle)
  fun X509_REQ_new : Handle
  fun X509_REQ_free(Handle)
  fun X509_REQ_set_version(Handle, LibC::Long) : Int32
  fun X509_REQ_set_pubkey(Handle, Handle) : Int32
  fun X509V3_EXT_conf_nid(Handle, Handle, Int32, UInt8*) : LibCrypto::X509_EXTENSION
  fun X509_EXTENSION_free(LibCrypto::X509_EXTENSION)
  fun OPENSSL_sk_new_null : Handle
  fun OPENSSL_sk_push(Handle, Handle) : Int32
  fun OPENSSL_sk_free(Handle)
  fun X509_REQ_add_extensions(Handle, Handle) : Int32
  fun X509_REQ_sign(Handle, Handle, LibCrypto::EVP_MD) : Int32
  fun i2d_X509_REQ(Handle, UInt8**) : Int32
  fun PEM_read_bio_X509(LibCrypto::Bio*, LibCrypto::X509*, Handle, Handle) : LibCrypto::X509
  fun X509_free(LibCrypto::X509)
  fun X509_check_host(LibCrypto::X509, UInt8*, LibC::SizeT, UInt32, UInt8**) : Int32
  fun X509_check_private_key(LibCrypto::X509, Handle) : Int32
  fun X509_get0_notBefore(LibCrypto::X509) : Handle
  fun X509_get0_notAfter(LibCrypto::X509) : Handle
  fun ASN1_TIME_to_tm(Handle, LibC::Tm*) : Int32
  fun X509_STORE_new : LibCrypto::X509_STORE
  fun X509_STORE_free(LibCrypto::X509_STORE)
  fun X509_STORE_set_default_paths(LibCrypto::X509_STORE) : Int32
  fun X509_STORE_CTX_new : LibCrypto::X509_STORE_CTX
  fun X509_STORE_CTX_free(LibCrypto::X509_STORE_CTX)
  fun X509_STORE_CTX_init(LibCrypto::X509_STORE_CTX, LibCrypto::X509_STORE, LibCrypto::X509, Handle) : Int32
end
