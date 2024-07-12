#ifndef __H_OPENSSL_CRYPTO_H__
#define __H_OPENSSL_CRYPTO_H__
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
#include <vector>
#include <string>
#include <sys/time.h>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include "base64.h"
#include <openssl/modes.h>
#include <openssl/aes.h>

#if OPENSSL_VERSION_NUMBER < 0x10101000L  
	assert(false && "OPENSSL_VERSION_NUMBER must be greater than 1.1.0");
#endif
enum Padding
{
    PADDING_NONE = 0,
    PADDING_PKCS7 = 1,
};
class Aes
{
public:
    static int getPKCS7PaddedLength(int dataLen, int alignSize)
	{
		// 计算填充的字节数（按alignSize字节对齐进行填充）
		int remainder = dataLen % alignSize;
		int paddingSize = (remainder == 0) ? alignSize : (alignSize - remainder);
		return (dataLen + paddingSize);
	}

	/**
	 * @brief PKCS7Padding
	 * 采用PKCS7Padding方式，将in数据进行alignSize字节对齐填充。
	 * 此函数用于加密前，对明文进行填充。
	 * @param in 数据
	 * @param alignSize 对齐字节数
	 * @return 返回填充后的数据
	 */
	static std::string PKCS7Padding(const std::string &in, int alignSize)
	{
		// 计算需要填充字节数（按alignSize字节对齐进行填充）
		int remainder = in.size() % alignSize;
		int paddingSize = (remainder == 0) ? alignSize : (alignSize - remainder);

		// 进行填充
		std::string temp(in);
		temp.append(paddingSize, paddingSize);
		return temp;
	}

	/**
	 * @brief PKCS7UnPadding
	 * 采用PKCS7Padding方式，将in数据去除填充。
	 * 此函数用于解密后，对解密结果进一步去除填充，以得到原始数据。
	 * @param in 数据
	 * @return 返回去除填充后的数据
	 */
	static std::string PKCS7UnPadding(const std::string &in)
	{
		char paddingSize = in.at(in.size() - 1);
		return in.substr(0, in.size() - paddingSize);
	}


	static std::string DoPad(const std::string &in, bool enc, Padding padding)
	{
		if (enc)
		{
			switch (padding)
			{
			case PADDING_PKCS7:
				// 进行PKCS7Padding填充
				return PKCS7Padding(in, AES_BLOCK_SIZE);
			default:
				return in;
			}
		}
		else
		{
			switch (padding)
			{
			case PADDING_PKCS7:
				// 解除PKCS7Padding填充
				return PKCS7UnPadding(in);
			default:
				return in;
			}
		}
	}

	static bool ecb_encrypt(const std::string &in, std::string &out, const std::string &key, bool enc, Padding padding)
	{    
		// 检查密钥合法性(只能是16、24、32字节)
		if (key.size() != 16 && key.size() != 24 && key.size() != 32)
		{
			return false;
		}

		if (enc)
		{
			// 生成加密key
			AES_KEY aes_key;
			if (AES_set_encrypt_key((const unsigned char*)key.data(), key.size() * 8, &aes_key) != 0)
			{
				return false;
			}

			std::string inTemp = DoPad(in, enc, padding);

			// 执行ECB模式加密
			out.resize(inTemp.size()); // 调整输出buf大小
			for (int i = 0; i < inTemp.size() / AES_BLOCK_SIZE; i++)
			{
				AES_ecb_encrypt((const unsigned char*)inTemp.data() + AES_BLOCK_SIZE * i,
								(unsigned char*)out.data() + AES_BLOCK_SIZE * i,
								&aes_key,
								AES_ENCRYPT);
			}
			return true;
		}
		else
		{
			// 生成解密key
			AES_KEY aes_key;
			if (AES_set_decrypt_key((const unsigned char*)key.data(), key.size() * 8, &aes_key) != 0)
			{
				return false;
			}

			// 执行ECB模式解密
			out.resize(in.size()); // 调整输出buf大小
			for (int i = 0; i < in.size() / AES_BLOCK_SIZE; i++)
			{
				AES_ecb_encrypt((const unsigned char*)in.data() + AES_BLOCK_SIZE * i,
								(unsigned char*)out.data() + AES_BLOCK_SIZE * i,
								&aes_key,
								AES_DECRYPT);
			}

			out = DoPad(out, enc, padding);
			return true;
		}
	}

	static bool cbc_encrypt(const std::string &in, std::string &out, const std::string &key, const std::string &ivec, bool enc, Padding padding)
	{
		// 检查密钥合法性(只能是16、24、32字节)
		if (key.size() != 16 && key.size() != 24 && key.size() != 32)
		{
			return false;
		}
		if (ivec.size() != 16) // 初始向量为16字节
		{
			return false;
		}

		if (enc)
		{
			// 生成加密key
			AES_KEY aes_key;
			if (AES_set_encrypt_key((const unsigned char*)key.data(), key.size() * 8, &aes_key) != 0)
			{
				return false;
			}

			std::string inTemp = DoPad(in, enc, padding);

			// 执行CBC模式加密
			std::string ivecTemp(ivec.data(), ivec.size()); // ivec会被修改，故需要临时变量来暂存
			out.resize(inTemp.size()); // 调整输出buf大小
			AES_cbc_encrypt((const unsigned char*)inTemp.data(),
							(unsigned char*)out.data(),
							inTemp.size(),
							&aes_key,
							(unsigned char*)ivecTemp.data(),
							AES_ENCRYPT);
			return true;
		}
		else
		{
			// 生成解密key
			AES_KEY aes_key;
			if (AES_set_decrypt_key((const unsigned char*)key.data(), key.size() * 8, &aes_key) != 0)
			{
				return false;
			}

			// 执行CBC模式解密
			std::string ivecTemp(ivec.data(), ivec.size()); // ivec会被修改，故需要临时变量来暂存
			out.resize(in.size()); // 调整输出buf大小
			AES_cbc_encrypt((const unsigned char*)in.data(),
							(unsigned char*)out.data(),
							in.size(),
							&aes_key,
							(unsigned char*)ivecTemp.data(),
							AES_DECRYPT);

			out = DoPad(out, enc, padding);
			return true;
		}
	}
};
enum ExportType
{
    EXPORT_TYPE_NONE = 0,
    EXPORT_TYPE_BASE64 = 1,
    EXPORT_TYPE_HEX = 2,
    EXPORT_TYPE_BASE64_URL = 3,
};

class CryptoUtils
{
public:

//********************************HASH********************************** */
		static std::string message_digest(const std::string &s, const EVP_MD *algo) {  
			// 使用 std::unique_ptr 管理 EVP_MD_CTX 的生命周期  
			auto context = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>(  
				EVP_MD_CTX_new(), EVP_MD_CTX_free);  
		
			if (!context) {  
				// 如果 EVP_MD_CTX_new() 失败，可以抛出一个异常或返回错误  
				throw std::runtime_error("Failed to create EVP_MD_CTX");  
			}  
		
			unsigned int hash_length = 0;  
			unsigned char hash[EVP_MAX_MD_SIZE];  
		
			// 初始化摘要上下文  
			if (EVP_DigestInit_ex(context.get(), algo, nullptr) != 1) {  
				// 如果初始化失败，可以抛出一个异常或返回错误  
				throw std::runtime_error("EVP_DigestInit_ex failed");  
			}  
		
			// 更新摘要上下文  
			if (EVP_DigestUpdate(context.get(), s.c_str(), s.size()) != 1) {  
				// 如果更新失败，可以抛出一个异常或返回错误  
				throw std::runtime_error("EVP_DigestUpdate failed");  
			}  
		
			// 完成摘要计算  
			if (EVP_DigestFinal_ex(context.get(), hash, &hash_length) != 1) {  
				// 如果最终计算失败，可以抛出一个异常或返回错误  
				throw std::runtime_error("EVP_DigestFinal_ex failed");  
			}  
		
			std::stringstream ss;  
			for (auto i = 0u; i < hash_length; ++i) {  
				ss << std::hex << std::setw(2) << std::setfill('0')  
				<< static_cast<unsigned int>(hash[i]);  
			}  
		
			return ss.str();  
		}

		static std::string MD5(const std::string &s) {
		return message_digest(s, EVP_md5());
		}

		static std::string SHA_256(const std::string &s) {
		return message_digest(s, EVP_sha256());
		}

		static std::string SHA_512(const std::string &s) {
		return message_digest(s, EVP_sha512());
		}

		static std::string SHA_1(const std::string &s) {
		return message_digest(s, EVP_sha1());
		}
//********************************编码解码********************************** */
	    static std::string Base64(const std::string& str, bool encode = true)
        {
            if (encode)
            {
                size_t len = Base64encode_len(str.size());
                std::string buf;
                buf.resize(len);
                int d_len = Base64encode((char*)buf.data(), str.c_str(), str.size());
                if (d_len > 0)
                {
                    buf = buf.substr(0, d_len);
                }
                return buf;
            }
            else 
            {	
                size_t len = Base64decode_len(str.c_str());
                std::string buf;
                buf.resize(len);
                int d_len = Base64decode((char*)buf.data(), str.c_str());
                if (d_len > 0)
                {
                    buf = buf.substr(0, d_len);
                }
                return buf;
            }
        }
        static std::string ToHexString(const std::string& str) {
            std::stringstream ss;
            for (size_t i = 0; i < str.size(); i++)
            {
                ss << std::setw(2)
                    << std::setfill('0')
                    << std::hex
                    << static_cast<int>(static_cast<unsigned char>(str.at(i)));
            }
            return ss.str();
        }
        static std::string FromHexString(const std::string& str) {
            if (str.size() % 2 != 0)
            {
                return "";
            }
            bool has_error = false;
            auto to_v = [&](char c)->std::int8_t{
                if (c >= '0' && c <= '9')
                {
                    return c - '0';
                }
                else if (c >= 'a' && c <= 'f')
                {
                    return c - 'a' + 10;
                }
                else if (c >= 'A' && c <= 'F')
                {
                    return c - 'A' + 10;
                }
                has_error = true;
                return 0;
            };

            std::string ss;
            ss.resize(str.size() / 2);
            for (size_t i = 0; i < ss.size(); i++)
            {
                std::int8_t v = to_v(str.at(i * 2));
                v <<= 4;
                v |= to_v(str.at(i * 2 + 1));
                ss[i] = v;
                
                if (has_error)
                {
                    return "";
                }
            }
            return ss;
        }
        static std::string Hex(const std::string& str, bool encode = true)
        {
            if (encode)
            {
                return ToHexString(str);
            }
            else
            {
                return FromHexString(str);
            }
        }

        static std::string Base64Url(const std::string& str, bool encode = true)
        {
            /*
            BASE64URL编码的流程：1、明文使用BASE64进行加密 2、在BASE64的基础上进行一下的编码：2.1)去除尾部的"=" 2.2)把"+"替换成"-" 2.3)把"/"替换成"_"
            BASE64URL解码的流程：1)把"-"替换成"+". 2)把"_"替换成"/" . 3)(计算BASE64URL编码长度)%4 a)结果为0，不做处理 b)结果为2，字符串添加"==" c)结果为3，字符串添加"="
            */
            if (encode)
            {
                std::string data = Base64(str, encode);
                // trim
                int len = 0;
                for (; len < data.size(); len++)
                {
                    if (data.at(data.size() - len - 1) != '=') break;
                }
                if (len < 0 || len >= data.size())
                {
                    return data;
                }
                data = data.substr(0, data.size() - len);
                for (int i = 0; i < data.size(); i++)
                {
                    switch (data.at(i))
                    {
                    case '+':
                        data[i] = '-';
                        break;
                    case '/':
                        data[i] = '_';
                        break;
                    default:
                        break;
                    }
                }
                return data;
            }
            else
            {
                std::string data = str;
                for (int i = 0; i < data.size(); i++)
                {
                    switch (data.at(i))
                    {
                    case '-':
                        data[i] = '+';
                        break;
                    case '_':
                        data[i] = '/';
                        break;
                    default:
                        break;
                    }
                }
                const int size = 16;
                int len_trim = size - (data.size() % size);
                for (int i = 0; i < len_trim; i++)
                {
                    data += '=';
                }
                return Base64(data, encode);
            }
        }
		
        /*
         只处理了'+'字符和'%'字符的情况。对于更复杂的情况，解码可能需要更多的处理。
        */
        // static Json::Value urlencoded_to_json(const std::string &urlencoded) {
        //     std::istringstream iss(urlencoded);
        //     Json::Value json_obj;
 
        //     for (std::string key_value; std::getline(iss, key_value, '&');) {
        //         auto pos = key_value.find('=');
        //         if (pos != std::string::npos) {
        //             std::string key = key_value.substr(0, pos);
        //             std::string value = key_value.substr(pos + 1);
        //             // Decode URL-encoded string
        //             // for (size_t i = 0; i < value.size(); ++i) {
        //             //     if (value[i] == '+') {
        //             //         value[i] = ' ';
        //             //     } else if (value[i] == '%') {
        //             //         int val = 0;
        //             //         sscanf(value.c_str() + i + 1, "%2x", &val);
        //             //         value[i] = static_cast<char>(val);
        //             //         value.erase(i + 1, 2);
        //             //     }
        //             // }
        //             json_obj[key] = value;
        //         }
        //     }
        //     return json_obj;
        // }

        static unsigned char ToHex(unsigned char x)   
        {   
            return  x > 9 ? x + 55 : x + 48;   
        }  
        
        static unsigned char FromHex(unsigned char x)   
        {   
            unsigned char y;  
            if (x >= 'A' && x <= 'Z') y = x - 'A' + 10;  
            else if (x >= 'a' && x <= 'z') y = x - 'a' + 10;  
            else if (x >= '0' && x <= '9') y = x - '0';  
            //else assert(0);  
            return y;  
        }
		static std::string UrlEncode(const std::string& str)  
        {  
            std::string strTemp = "";  
            size_t length = str.length();  
            for (size_t i = 0; i < length; i++)  
            {  
                if (isalnum((unsigned char)str[i]) ||
                    (str[i] == '-') ||  
                    (str[i] == '_') ||   
                    (str[i] == '.') ||   
                    (str[i] == '~'))  
                    strTemp += str[i];  
                else if (str[i] == ' ')  
                    strTemp += "+";  
                else  
                {  
                    strTemp += '%';  
                    strTemp += ToHex((unsigned char)str[i] >> 4);  
                    strTemp += ToHex((unsigned char)str[i] % 16);  
                }  
            }  
            return strTemp;  
        }  

		static std::string UrlDecode(const std::string& str)  
        {  
            std::string strTemp = "";  
            size_t length = str.length();  
            for (size_t i = 0; i < length; i++)  
            {  
                if (str[i] == '+') strTemp += ' ';  
                else if (str[i] == '%')  
                {  
                    //assert(i + 2 < length);  
                    unsigned char high = FromHex((unsigned char)str[++i]);  
                    unsigned char low = FromHex((unsigned char)str[++i]);  
                    strTemp += high*16 + low;  
                }  
                else strTemp += str[i];  
            }  
            return strTemp;  
        }
//*****************************AES加解密*************************************** */
         static std::string ExportString(const std::string& data, bool encode = true, ExportType et = EXPORT_TYPE_BASE64)
        {
            switch (et)
            {
            case EXPORT_TYPE_BASE64:
                return Base64(data, encode);
            case EXPORT_TYPE_HEX:
                return Hex(data, encode);
            case EXPORT_TYPE_BASE64_URL:
                return Base64Url(data, encode);
            default:
                break;
            }
            return "";
        }
		static std::string AesEcb(const std::string& key, const std::string& data, bool encode, ExportType et = EXPORT_TYPE_BASE64, Padding padding = PADDING_PKCS7) 
        {
            if (encode)
            {
                std::string data_out;
                if (!Aes::ecb_encrypt(data, data_out, key, true, padding))
                {
                    return "";
                }
                return ExportString(data_out, true, et);
            }
            else
            {
                std::string data_in = ExportString(data, false, et);
                std::string data_out = "";
                if (!Aes::ecb_encrypt(data_in, data_out, key, false, padding))
                {
                    return "";
                }
                return data_out;
            }
        }
        static std::string AesCbc(const std::string& key, const std::string& iv, const std::string& data, bool encode, ExportType et = EXPORT_TYPE_BASE64, Padding padding = PADDING_PKCS7) 
        {
            if (encode)
            {
                std::string data_out;
                if (!Aes::cbc_encrypt(data, data_out, key, iv, true, padding))
                {
                    return "";
                }
                return ExportString(data_out, true, et);
            }
            else
            {
                std::string data_in = ExportString(data, false, et);
                std::string data_out = "";
                if (!Aes::cbc_encrypt(data_in, data_out, key, iv, false, padding))
                {
                    return "";
                }
                return data_out;
            }
        }

};
#endif
#endif