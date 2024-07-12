//#include "crypto.h"
#include <string>
#include <iostream>
#include <iomanip>
#include <openssl/aes.h>  
#include <openssl/evp.h>  
#include <iostream>  
#include <string>  
#include <vector>
#include "cryptoUtils.h"



int main()
{
     std::string plaintext = "HelloWorld!";
    //测试md5加密
    std::cout << "md5加密" << CryptoUtils::MD5(plaintext) << std::endl;
    //测试sha1加密
    std::cout << "sha1加密" << CryptoUtils::SHA_1(plaintext) << std::endl;
    //测试sha256加密
    std::cout << "sha256加密" << CryptoUtils::SHA_256(plaintext) << std::endl;
    //测试sha512加密
    std::cout << "sha512加密" << CryptoUtils::SHA_512(plaintext) << std::endl;

    std::string aes_key_128 = "c28540d871bd8ea6"; // 16字节AES-128密钥  
    std::string aes_iv_128 =  "857d3a5fca54219a";   // 16字节AES-128 CBC IV  
    //测试AES CBC 128加密 ExportType et = EXPORT_TYPE_BASE64, Padding padding = PADDING_PKCS7
    std::string aes_cbc_128_encrypted = CryptoUtils::AesCbc(aes_key_128, aes_iv_128, plaintext, true, EXPORT_TYPE_BASE64, PADDING_PKCS7); 
    std::cout << "aes_cbc_128加密" << aes_cbc_128_encrypted << std::endl;
    //测试AES CBC 128解密
    std::cout << "aes_cbc_128解密" << CryptoUtils::AesCbc(aes_key_128, aes_iv_128, aes_cbc_128_encrypted, false, EXPORT_TYPE_BASE64, PADDING_PKCS7) << std::endl;

    //测试AES CBC 256加密
    std::string aes_key_256 = "1234567890abcdef1234567890abcdef"; // 32字节AES-256密钥  
    std::string aes_iv_256 = "abcdef9012345678";   // 16字节AES-256 CBC IV  
    std::string aes_cbc_256_encrypted = CryptoUtils::AesCbc(aes_key_256, aes_iv_256, plaintext, true, EXPORT_TYPE_BASE64, PADDING_PKCS7);
    std::cout << "aes_cbc_256加密" << aes_cbc_256_encrypted << std::endl;
        //测试AES CBC 256解密
    std::cout << "aes_cbc_256解密" << CryptoUtils::AesCbc(aes_key_256, aes_iv_256, aes_cbc_256_encrypted, false, EXPORT_TYPE_BASE64, PADDING_PKCS7) << std::endl;


//     //测试DES_EBC 解密

//     // std::cout << "des_ebc解密" << CryptoUtil::DES_EBC_DECRY(key, des_ebc_encrypted) << std::endl;
//     // //测试DES CBC 解密
//     // std::cout << "des_cbc解密" << CryptoUtil::DES_CBC_DECRY(key, iv, des_cbc_encrypted) << std::endl;
//     //测试AES CBC 256解密
//     //std::cout << "aes_cbc_256解密" << CryptoUtil::AES_CBC_256_DECRY(aes_key_256, aes_iv_256, aes_cbc_256_encrypted) << std::endl;
//     //return 0;
    return 0;
}
// 函数原型声明  
// std::string aesEncrypt(const std::string& plaintext, const std::string& key, const std::string& iv, const EVP_CIPHER *algo);  

// // 辅助函数：将二进制数据转换为Base64编码的字符串  
// std::string base64_encode(const unsigned char* buf, size_t len) {  
//     BIO *bio, *b64;  
//     std::string out;  
  
//     b64 = BIO_new(BIO_f_base64());  
//     BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // 不添加换行符  
//     bio = BIO_new(BIO_s_mem());  
//     bio = BIO_push(b64, bio);  
  
//     BIO_write(bio, buf, len);  
//     BIO_flush(bio);  
  
//     // 读取编码后的数据  
//     char buf_out[4096];  
//     int len_read;  
//     while ((len_read = BIO_read(bio, buf_out, sizeof(buf_out) - 1)) > 0) {  
//         out.append(buf_out, len_read);  
//     }  
  
//     BIO_free_all(bio);  
  
//     return out;  
// }
  
// // 更安全的版本，使用BIO_read()  
// std::vector<unsigned char> base64_decode(const std::string& encoded) {  
//     BIO *bio, *b64;  
//     std::vector<unsigned char> decoded;  
  
//     b64 = BIO_new(BIO_f_base64());  
//     BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);  
  
//     bio = BIO_new_mem_buf(encoded.c_str(), -1); // 使用内存BIO并传递Base64编码的字符串  
//     bio = BIO_push(b64, bio);  
  
//     // 读取解码后的数据  
//     char buf[4096]; // 临时缓冲区  
//     int len;  
//     while ((len = BIO_read(bio, buf, sizeof(buf) - 1)) > 0) {  
//         decoded.insert(decoded.end(), reinterpret_cast<unsigned char*>(buf), reinterpret_cast<unsigned char*>(buf) + len);  
//     }  
  
//     BIO_free_all(bio);  
  
//     return decoded;  
// }  

// // 加密函数  
// std::string aesEncrypt(const std::string& plaintext, const std::string& key, const std::string& iv, const EVP_CIPHER *algo) {  
//      if (key.size() != EVP_CIPHER_key_length(algo) || iv.size() != EVP_CIPHER_iv_length(algo)) {  
//         throw std::invalid_argument("Key or IV length is incorrect");  
//     }  
//     std::string padded_plaintext = plaintext;
//     // 加密输出缓冲区  
//     std::vector<unsigned char> ciphertext(padded_plaintext.size() + AES_BLOCK_SIZE);  
  
//     // 加密上下文  
//     EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();  
//     if (!ctx) {  
//         std::cerr << "Failed to create cipher context" << std::endl;  
//         return "";  
//     }  
  
//     // 初始化加密  
//     if (1 != EVP_EncryptInit_ex(ctx, algo, NULL,  
//                                 reinterpret_cast<const unsigned char*>(key.data()),  
//                                 reinterpret_cast<const unsigned char*>(iv.data()))) {  
//         std::cerr << "Failed to initialize encryption" << std::endl;  
//         EVP_CIPHER_CTX_free(ctx);  
//         return "";  
//     }  
  
//     int len;  
//     // 执行加密  
//     if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len,  
//                                reinterpret_cast<const unsigned char*>(padded_plaintext.data()), padded_plaintext.size())) {  
//         std::cerr << "Failed to encrypt data" << std::endl;  
//         EVP_CIPHER_CTX_free(ctx);  
//         return "";  
//     }  
  
//     int ciphertext_len = len;  
  
//     // 完成加密  
//     if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) {  
//         std::cerr << "Failed to finalize encryption" << std::endl;  
//         EVP_CIPHER_CTX_free(ctx);  
//         return "";  
//     }  
//     ciphertext_len += len;  
  
//     // 清理  
//     EVP_CIPHER_CTX_free(ctx);  
  
//     // 将二进制密文转换为十六进制字符串（可选）  
//     // std::stringstream ss;  
//     // for (size_t i = 0; i < ciphertext_len; i++) {  
//     //     ss << std::hex << std::setw(2) << std::setfill('0') << (int)ciphertext[i];  
//     // }  

//     for (size_t i = 0; i < ciphertext_len; i++) {  
//        cout  << (int)ciphertext[i];  
//     }  
//     // return ss.str();

//     // 将加密后的二进制数据转换为Base64编码的字符串  
//     return base64_encode(ciphertext.data(), ciphertext_len); 
// }

// // 函数原型声明  
// std::string aesDecrypt(const std::string& ciphertext_hex, const std::string& key, const std::string& iv, const EVP_CIPHER *algo);  
  
// // 辅助函数：将十六进制字符串转换为二进制数据  
// std::vector<unsigned char> hexStringToBytes(const std::string& hex_str) {  
//     std::vector<unsigned char> bytes;  
//     for (size_t i = 0; i < hex_str.size(); i += 2) {  
//         std::string byte_str = hex_str.substr(i, 2);  
//         char *end;  
//         unsigned long val = std::strtoul(byte_str.c_str(), &end, 16);  
//         if (end != byte_str.c_str() + 2) {  
//             throw std::runtime_error("Invalid hex string");  
//         }  
//         bytes.push_back(static_cast<unsigned char>(val));  
//     }  
//     return bytes;  
// }  
  
// // 解密函数  
// std::string aesDecrypt(const std::string& ciphertext_hex, const std::string& key, const std::string& iv, const EVP_CIPHER *algo) {  
//      if (key.size() != EVP_CIPHER_key_length(algo) || iv.size() != EVP_CIPHER_iv_length(algo)) {  
//         throw std::invalid_argument("Key or IV length is incorrect");  
//     }  
  
//     // 将十六进制密文转换为二进制  
//     //std::vector<unsigned char> ciphertext = hexStringToBytes(ciphertext_hex);
//     std::vector<unsigned char> ciphertext = base64_decode(ciphertext_hex); 
  
//     // 解密输出缓冲区  
//     std::vector<unsigned char> decryptedtext(ciphertext.size());  
  
//     // 解密上下文  
//     EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();  
//     if (!ctx) {  
//         std::cerr << "Failed to create cipher context" << std::endl;  
//         return "";  
//     }  
  
//     // 初始化解密  
//     if (1 != EVP_DecryptInit_ex(ctx, algo, NULL,  
//                                 reinterpret_cast<const unsigned char*>(key.data()),  
//                                 reinterpret_cast<const unsigned char*>(iv.data()))) {  
//         std::cerr << "Failed to initialize decryption" << std::endl;  
//         EVP_CIPHER_CTX_free(ctx);  
//         return "";  
//     }  
  
//     int len;  
//     int decryptedtext_len;  
  
//     // 执行解密  
//     if (1 != EVP_DecryptUpdate(ctx, decryptedtext.data(), &len, ciphertext.data(), ciphertext.size())) {  
//         std::cerr << "Failed to decrypt data" << std::endl;  
//         EVP_CIPHER_CTX_free(ctx);  
//         return "";  
//     }  
//     decryptedtext_len = len;  
  
//     // 完成解密  
//     if (1 != EVP_DecryptFinal_ex(ctx, decryptedtext.data() + len, &len)) {  
//         // 注意：如果数据被正确填充，这里通常不会出错  
//         // 如果出错，可能是填充不正确或密文被篡改  
//         std::cerr << "Failed to finalize decryption" << std::endl;  
//         EVP_CIPHER_CTX_free(ctx);  
//         return "";  
//     }  
//     decryptedtext_len += len;  
  
//     // 移除填充（如果需要的话）  
//     // 注意：这个简单的示例没有实现自动填充移除，因为它依赖于特定的填充方案  
//     // 在实际应用中，你可能需要根据你的填充方案来移除填充  
  
//     // 清理  
//     EVP_CIPHER_CTX_free(ctx);  
  
//     // 将二进制解密文本转换为字符串（注意：这可能会包含不可打印字符）  
//     std::string result(reinterpret_cast<char*>(decryptedtext.data()), decryptedtext_len);  
  
//     return result;  
// }
  
// int main() {  
//     std::string key = "0123456789abcdef"; // 16字节的AES密钥  
//     std::string iv = "abcdef9876543210";  // 16字节的IV  
//     std::string plaintext = "Hello, World!";  
  
//     std::string ciphertext = aesEncrypt(plaintext, key, iv, EVP_aes_128_cbc());  
//     std::cout << "Ciphertext aes 128 cbc加密(hex): " << ciphertext << std::endl;
//     //解密
//     std::cout << "Ciphertext aes 128 cbc 解密(hex): " <<  aesDecrypt(ciphertext, key, iv, EVP_aes_128_cbc()) << std::endl;

//     // std::string aes_key_256 = "1234567890abcdef1234567890abcdef"; // 32字节AES-256密钥  
//     // std::string aes_iv_256 = "abcdef9012345678";   // 16字节AES-256 CBC IV  
//     // std::string aes_cbc_256_encrypted = aesEncrypt(plaintext, aes_key_256, aes_iv_256, EVP_aes_256_cbc());  
//     // std::cout << "aes_cbc_256加密(hex): " << aes_cbc_256_encrypted << std::endl;
//     //     //解密
//     // std::cout << "Ciphertext aes 256 cbc 解密(hex): " <<  aesDecrypt(aes_cbc_256_encrypted, aes_key_256, aes_iv_256, EVP_aes_256_cbc()) << std::endl;
//     return 0;  
// }


// // int main()
// // {
// //     std::string plaintext = "HelloWorld!";
//     // //测试md5加密
//     // std::cout << "md5加密" << CryptoUtil::MD5(plaintext) << std::endl;
//     // //测试sha1加密
//     // std::cout << "sha1加密" << CryptoUtil::SHA_1(plaintext) << std::endl;
//     // //测试sha256加密
//     // std::cout << "sha256加密" << CryptoUtil::SHA_256(plaintext) << std::endl;
//     // //测试sha512加密
//     // std::cout << "sha512加密" << CryptoUtil::SHA_512(plaintext) << std::endl;

//     // std::string key = "12345678"; // 8字节DES密钥  
//     // std::string iv = "12345678";  // 8字节DES CBC IV  
//     //测试DES_EBC 加密
//     // std::string des_ebc_encrypted = CryptoUtil::DES_EBC_ENCRY(key, plaintext);  
//     // std::cout << "des_ebc加密" << des_ebc_encrypted << std::endl;
//     // //测试DES CBC 加密
//     // std::string des_cbc_encrypted = CryptoUtil::DES_CBC_ENCRY(key, iv, plaintext);  
//     // std::cout << "des_cbc加密" << des_cbc_encrypted << std::endl;

//     //std::string aes_key_128 = "c28540d871bd8ea6"; // 16字节AES-128密钥  
//     //std::string aes_iv_128 =  "857d3a5fca54219a";   // 16字节AES-128 CBC IV  
//     //测试AES CBC 128加密
//     // std::string aes_cbc_128_encrypted = CryptoUtil::AES_CBC_128_ENCRY(aes_key_128, aes_iv_128, plaintext); 
//     // std::cout << "aes_cbc_128加密" << aes_cbc_128_encrypted << std::endl;
//      //测试AES CBC 128解密
//     //std::cout << "aes_cbc_128解密" << CryptoUtil::AES_CBC_128_DECRY(aes_key_128, aes_iv_128, aes_cbc_128_encrypted) << std::endl;

//     //std::string aes_cbc_128_encrypted1 = CryptoUtil::AesEcb(aes_key_128, plaintext, true, EXPORT_TYPE_HEX);
//     // std::string aes_cbc_128_encrypted1 = CryptoUtil::AesCbc(aes_key_128, aes_iv_128, plaintext, true, EXPORT_TYPE_HEX);
//     // std::cout << "aes_cbc_128 普通库加密" << aes_cbc_128_encrypted1 << std::endl;
//     //测试AES CBC 256加密
//     // std::string aes_key_256 = "1234567890abcdef1234567890abcdef"; // 32字节AES-256密钥  
//     // std::string aes_iv_256 = "abcdef9012345678";   // 16字节AES-256 CBC IV  
//     // std::string aes_cbc_256_encrypted = CryptoUtil::AES_CBC_256_ENCRY(aes_key_256, aes_iv_256, plaintext);  
//     // std::cout << "aes_cbc_256加密" << aes_cbc_256_encrypted << std::endl;


//     //测试DES_EBC 解密

//     // std::cout << "des_ebc解密" << CryptoUtil::DES_EBC_DECRY(key, des_ebc_encrypted) << std::endl;
//     // //测试DES CBC 解密
//     // std::cout << "des_cbc解密" << CryptoUtil::DES_CBC_DECRY(key, iv, des_cbc_encrypted) << std::endl;
//     //测试AES CBC 256解密
//     //std::cout << "aes_cbc_256解密" << CryptoUtil::AES_CBC_256_DECRY(aes_key_256, aes_iv_256, aes_cbc_256_encrypted) << std::endl;
//     //return 0;
// //}

// /*
// 加密： printf "HelloWorld!" | openssl enc -aes-128-cbc -e -K c28540d871bd8ea669098540be58fef5 -iv 857d3a5fca54219a068a5c4dd9615afb | xxd -p

// 加密： printf "HelloWorld!" | openssl enc -aes-128-cbc -e -K "c28540d871bd8ea6" -iv "857d3a5fca54219a" | xxd -p

// 解密：openssl aes-128-cbc -d -in encrypt.bin -out decode.bin -K c28540d871bd8ea669098540be58fef5 -iv 857d3a5fca54219a068a5c4dd9615afb -p -nopad


// */