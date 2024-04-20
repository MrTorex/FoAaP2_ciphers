#pragma once
#include <iomanip>
#include <iostream>
#include <sstream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

// ������� ���������� � ������������ ������ ������
inline std::string caesar_cipher(const std::string& plain_text, int shift)
{
    std::string result;
    // ����������� ����������� ������ �� ������ ����� �������� shift
    const int direction = shift >= 0 ? 1 : -1;
    // ������ ������ �� ������ (����������� � ������ ���� �� �������������, �.�. ����� �� ������ �����)
    shift = std::abs(shift);

    for (const char c : plain_text)
    {
        // ���������, �������� �� ������ ������
        if (isalpha(c))
        {
            // ���������� "������" (������� ��� ������ �������, �� ���� ����� ��� ���� ����������)
            const char start = isupper(c) ? 'A' : 'a';
            // ��������� ����� � ������ ��������� ������� � �������� � �����������
            const char encrypted_char = static_cast<char>(start + ((c - start + shift * direction) % 26 + 26) % 26);
            result += encrypted_char;
        }
        else
        {
            // ���� ������ �� �������� ������, ��������� ��� ��� ���������
            result += c;
        }
    }

    return result;
}

// ������� ���������� � ������������ ������ ��������
inline std::string vigenere_cipher(const std::string& text, const std::string& key, const bool encrypt)
{
    std::string result;
    const int key_length = static_cast<int>(key.length());
    // ������������� ����������� � ����������� �� �������� (���������� ��� �������������)
    const int direction = encrypt ? 1 : -1;

    for (int i = 0; i < static_cast<int>(text.length()); ++i)
    {
        const char current_char = text[i];
        // ���������, �������� �� ������ ������
        if (isalpha(current_char))
        {
            // ���������� "������" (������� ��� ������ �������, �� ���� ����� ��� ���� ����������)
            const char start = isupper(current_char) ? 'A' : 'a';
            // �������� ������ ������� �����
            const int key_index = i % key_length;
            // ��������� ����� � ������ ��������� ������� � ��������, ����� � �����������
            const char encrypted_char = static_cast<char>(start + (((current_char - start) + direction * (key[key_index] - 'A')) % 26 + 26) % 26);
            result += encrypted_char;
        }
        else
        {
            // ���� ������ �� �������� ������, ��������� ��� ��� ���������
            result += current_char;
        }
    }

    return result;
}

// ������� ��� ���������� ������ ������� E2EE
inline std::string encrypt_data_etee(const std::string& plaintext, const std::string& key)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::string result;

    // ������������� ����������
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, reinterpret_cast<const unsigned char*>(key.c_str()), nullptr);

    // ��������� ����� ������������ ������
    const int c_len = static_cast<int>(plaintext.length() + EVP_CIPHER_block_size(EVP_aes_256_cbc()) - 1);
    const auto result_buf = new unsigned char[c_len];

    // ���������� ������
    int len;
    EVP_EncryptUpdate(ctx, result_buf, &len, reinterpret_cast<const unsigned char*>(plaintext.c_str()), static_cast<int>(plaintext.length()));
    result.append(reinterpret_cast<char*>(result_buf), len);

    // ���������� ����������
    EVP_EncryptFinal_ex(ctx, result_buf + len, &len);
    result.append(reinterpret_cast<char*>(result_buf), len);

    // ������������ ������
    delete[] result_buf;
    EVP_CIPHER_CTX_free(ctx);

    return result;
}

// ������� ��� ����������� ������ ������� E2EE
inline std::string decrypt_data_etee(const std::string& result, const std::string& key)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::string plaintext;

    // ������������� �����������
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, reinterpret_cast<const unsigned char*>(key.c_str()), nullptr);

    // ��������� ����� ��������������� ������
    const int p_len = static_cast<int>(result.length() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    const auto plaintext_buf = new unsigned char[p_len];

    // ����������� ������
    int len;
    EVP_DecryptUpdate(ctx, plaintext_buf, &len, reinterpret_cast<const unsigned char*>(result.c_str()), result.length());
    plaintext.append(reinterpret_cast<char*>(plaintext_buf), len);

    // ���������� �����������
    EVP_DecryptFinal_ex(ctx, plaintext_buf + len, &len);
    plaintext.append(reinterpret_cast<char*>(plaintext_buf), len);

    // ������������ ������
    delete[] plaintext_buf;
    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
}

// ������� ��� ����������� ������
inline std::string hash_data(const std::string& data)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned int md_len;

    // �������� ��������� �����������
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();

    if (!mdctx)
    {
        std::cerr << "������: �� ������� ������� �������� �����������.\n";
        return "";
    }

    // ������������� ��������� ����������� ��� SHA-25
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1)
    {
        std::cerr << "������: �� ������� ���������������� �������� ����������� ��� SHA-256.\n";
        EVP_MD_CTX_free(mdctx);
        return "";
    }

    // ���������� ��������� ����������� � �������
    if (EVP_DigestUpdate(mdctx, data.c_str(), data.length()) != 1)
    {
        std::cerr << "������: �� ������� �������� �������� �����������.\n";
        EVP_MD_CTX_free(mdctx);
        return "";
    }

    // ��������� ����
    if (EVP_DigestFinal_ex(mdctx, hash, &md_len) != 1)
    {
        std::cerr << "������: �� ������� �������� ���.\n";
        EVP_MD_CTX_free(mdctx);
        return "";
    }

    // ������������ ��������� �����������
    EVP_MD_CTX_free(mdctx);

    // �������������� ������ ���� � ������ ������������������ �������������
    std::stringstream ss;
    for (unsigned int i = 0; i < md_len; ++i)
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);

    return ss.str();
}

// ������� ��� �������� ������������ ���-�������� ������� ������
inline bool verify_hash(const std::string& data, const std::string& expected_hash)
{
    const std::string hashed_data = hash_data(data);
    return hashed_data == expected_hash;
}