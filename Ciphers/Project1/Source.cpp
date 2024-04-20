
#include "ciphres.h"
#include <conio.h>

int main()
{
    setlocale(LC_ALL, "Russian");

    std::string input_text;
    std::cout << "Введите строку для шифрования: ";
    std::getline(std::cin, input_text);

    std::cout << "Выберите метод шифрования ('C' - Цезарь, 'V' - Виженер, 'E' - E2EE, 'H' - Хеширование):\n";

    switch (tolower(_getch()))
    {
    case 'c':
    {
        int shift;
        std::cout << "Введите сдвиг для шифра Цезаря: ";
        std::cin >> shift;

        // Шифрование строки шифром Цезаря
        std::string encrypted_text = caesar_cipher(input_text, shift);
        std::cout << "Зашифрованная строка (шифр Цезаря): " << encrypted_text << '\n';

        // Расшифровка строки шифром Цезаря
        std::string decrypted_text = caesar_cipher(encrypted_text, -shift);
        std::cout << "Расшифрованная строка (шифр Цезаря): " << decrypted_text << '\n';

        break;
    }
    case 'v':
    {
        std::string key;
        std::cout << "Введите ключ для шифра Виженера: ";
        std::cin >> key;

        // Шифрование строки шифром Виженера
        std::string encrypted_text = vigenere_cipher(input_text, key, true);
        std::cout << "Зашифрованная строка (шифр Виженера): " << encrypted_text << '\n';

        // Расшифровка строки шифром Виженера
        std::string decrypted_text = vigenere_cipher(encrypted_text, key, false);
        std::cout << "Расшифрованная строка (шифр Виженера): " << decrypted_text << '\n';

        break;
    }
    case 'e':
    {
        std::string key;
        std::cout << "Введите ключ для E2EE: ";
        std::cin >> key;

        // Шифрование данных методом E2EE
        std::string encrypted_text = encrypt_data_etee(input_text, key);
        std::cout << "Зашифрованные данные (E2EE): " << encrypted_text << '\n';

        // Расшифровка данных методом E2EE
        std::string decrypted_text = decrypt_data_etee(encrypted_text, key);
        std::cout << "Расшифрованные данные (E2EE): " << decrypted_text << '\n';

        break;
    }
    case 'h':
    {
        // Хеширование строки
        std::string hashed_text = hash_data(input_text);
        std::cout << "Хеш-значение для входной строки: " << hashed_text << '\n';

        // Проверка соответствия хеш-значения исходным данным
        std::string expected_hash;
        std::cout << "Введите ожидаемое хеш-значение: ";
        std::cin >> expected_hash;

        if (verify_hash(input_text, expected_hash))
            std::cout << "Хеш-значение соответствует исходным данным." << '\n';
        else
            std::cout << "Хеш-значение не соответствует исходным данным." << '\n';

        break;
    }
    default:
        std::cout << "Неверный метод шифрования. Выход из программы." << std::endl;
    }

    std::cout << "Нажмите любую клавишу для выхода...";
    _getch();

	return 0;
}