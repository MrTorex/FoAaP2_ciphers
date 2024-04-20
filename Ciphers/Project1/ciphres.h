#pragma once
#include <iomanip>
#include <iostream>
#include <sstream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

// Функция шифрования и дешифрования шифром Цезаря
inline std::string caesar_cipher(const std::string& plain_text, int shift)
{
    std::string result;
    // Определение направления сдвига на основе знака значения shift
    const int direction = shift >= 0 ? 1 : -1;
    // Возьмём модуль от сдвига (понадобится в случае если он отрицательный, т.е. сдвиг на модуль влево)
    shift = std::abs(shift);

    for (const char c : plain_text)
    {
        // Проверяем, является ли символ буквой
        if (isalpha(c))
        {
            // Определяем "начало" (верхний или нижний регистр, от него будет уже идти шифрование)
            const char start = isupper(c) ? 'A' : 'a';
            // Применяем сдвиг с учетом начальной позиции в алфавите и направления
            const char encrypted_char = static_cast<char>(start + ((c - start + shift * direction) % 26 + 26) % 26);
            result += encrypted_char;
        }
        else
        {
            // Если символ не является буквой, оставляем его без изменений
            result += c;
        }
    }

    return result;
}

// Функция шифрования и дешифрования шифром Виженера
inline std::string vigenere_cipher(const std::string& text, const std::string& key, const bool encrypt)
{
    std::string result;
    const int key_length = static_cast<int>(key.length());
    // Устанавливаем направление в зависимости от операции (шифрование или расшифрование)
    const int direction = encrypt ? 1 : -1;

    for (int i = 0; i < static_cast<int>(text.length()); ++i)
    {
        const char current_char = text[i];
        // Проверяем, является ли символ буквой
        if (isalpha(current_char))
        {
            // Определяем "начало" (верхний или нижний регистр, от него будет уже идти шифрование)
            const char start = isupper(current_char) ? 'A' : 'a';
            // Получаем индекс символа ключа
            const int key_index = i % key_length;
            // Применяем сдвиг с учетом начальной позиции в алфавите, ключа и направления
            const char encrypted_char = static_cast<char>(start + (((current_char - start) + direction * (key[key_index] - 'A')) % 26 + 26) % 26);
            result += encrypted_char;
        }
        else
        {
            // Если символ не является буквой, оставляем его без изменений
            result += current_char;
        }
    }

    return result;
}

// Функция для шифрования данных методом E2EE
inline std::string encrypt_data_etee(const std::string& plaintext, const std::string& key)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::string result;

    // Инициализация шифрования
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, reinterpret_cast<const unsigned char*>(key.c_str()), nullptr);

    // Получение длины шифрованного текста
    const int c_len = static_cast<int>(plaintext.length() + EVP_CIPHER_block_size(EVP_aes_256_cbc()) - 1);
    const auto result_buf = new unsigned char[c_len];

    // Шифрование данных
    int len;
    EVP_EncryptUpdate(ctx, result_buf, &len, reinterpret_cast<const unsigned char*>(plaintext.c_str()), static_cast<int>(plaintext.length()));
    result.append(reinterpret_cast<char*>(result_buf), len);

    // Завершение шифрования
    EVP_EncryptFinal_ex(ctx, result_buf + len, &len);
    result.append(reinterpret_cast<char*>(result_buf), len);

    // Освобождение памяти
    delete[] result_buf;
    EVP_CIPHER_CTX_free(ctx);

    return result;
}

// Функция для расшифровки данных методом E2EE
inline std::string decrypt_data_etee(const std::string& result, const std::string& key)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::string plaintext;

    // Инициализация расшифровки
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, reinterpret_cast<const unsigned char*>(key.c_str()), nullptr);

    // Получение длины расшифрованного текста
    const int p_len = static_cast<int>(result.length() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    const auto plaintext_buf = new unsigned char[p_len];

    // Расшифровка данных
    int len;
    EVP_DecryptUpdate(ctx, plaintext_buf, &len, reinterpret_cast<const unsigned char*>(result.c_str()), result.length());
    plaintext.append(reinterpret_cast<char*>(plaintext_buf), len);

    // Завершение расшифровки
    EVP_DecryptFinal_ex(ctx, plaintext_buf + len, &len);
    plaintext.append(reinterpret_cast<char*>(plaintext_buf), len);

    // Освобождение памяти
    delete[] plaintext_buf;
    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
}

// Функция для хеширования данных
inline std::string hash_data(const std::string& data)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned int md_len;

    // Создание контекста хеширования
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();

    if (!mdctx)
    {
        std::cerr << "Ошибка: Не удалось создать контекст хеширования.\n";
        return "";
    }

    // Инициализация контекста хеширования для SHA-25
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1)
    {
        std::cerr << "Ошибка: Не удалось инициализировать контекст хеширования для SHA-256.\n";
        EVP_MD_CTX_free(mdctx);
        return "";
    }

    // Обновление контекста хеширования с данными
    if (EVP_DigestUpdate(mdctx, data.c_str(), data.length()) != 1)
    {
        std::cerr << "Ошибка: Не удалось обновить контекст хеширования.\n";
        EVP_MD_CTX_free(mdctx);
        return "";
    }

    // Получение хеша
    if (EVP_DigestFinal_ex(mdctx, hash, &md_len) != 1)
    {
        std::cerr << "Ошибка: Не удалось получить хеш.\n";
        EVP_MD_CTX_free(mdctx);
        return "";
    }

    // Освобождение контекста хеширования
    EVP_MD_CTX_free(mdctx);

    // Преобразование байтов хеша в строку шестнадцатеричного представления
    std::stringstream ss;
    for (unsigned int i = 0; i < md_len; ++i)
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);

    return ss.str();
}

// Функция для проверки соответствия хеш-значения входным данным
inline bool verify_hash(const std::string& data, const std::string& expected_hash)
{
    const std::string hashed_data = hash_data(data);
    return hashed_data == expected_hash;
}