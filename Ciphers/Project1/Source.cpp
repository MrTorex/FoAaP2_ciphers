
#include "ciphres.h"
#include <conio.h>

int main()
{
    setlocale(LC_ALL, "Russian");

    std::string input_text;
    std::cout << "������� ������ ��� ����������: ";
    std::getline(std::cin, input_text);

    std::cout << "�������� ����� ���������� ('C' - ������, 'V' - �������, 'E' - E2EE, 'H' - �����������):\n";

    switch (tolower(_getch()))
    {
    case 'c':
    {
        int shift;
        std::cout << "������� ����� ��� ����� ������: ";
        std::cin >> shift;

        // ���������� ������ ������ ������
        std::string encrypted_text = caesar_cipher(input_text, shift);
        std::cout << "������������� ������ (���� ������): " << encrypted_text << '\n';

        // ����������� ������ ������ ������
        std::string decrypted_text = caesar_cipher(encrypted_text, -shift);
        std::cout << "�������������� ������ (���� ������): " << decrypted_text << '\n';

        break;
    }
    case 'v':
    {
        std::string key;
        std::cout << "������� ���� ��� ����� ��������: ";
        std::cin >> key;

        // ���������� ������ ������ ��������
        std::string encrypted_text = vigenere_cipher(input_text, key, true);
        std::cout << "������������� ������ (���� ��������): " << encrypted_text << '\n';

        // ����������� ������ ������ ��������
        std::string decrypted_text = vigenere_cipher(encrypted_text, key, false);
        std::cout << "�������������� ������ (���� ��������): " << decrypted_text << '\n';

        break;
    }
    case 'e':
    {
        std::string key;
        std::cout << "������� ���� ��� E2EE: ";
        std::cin >> key;

        // ���������� ������ ������� E2EE
        std::string encrypted_text = encrypt_data_etee(input_text, key);
        std::cout << "������������� ������ (E2EE): " << encrypted_text << '\n';

        // ����������� ������ ������� E2EE
        std::string decrypted_text = decrypt_data_etee(encrypted_text, key);
        std::cout << "�������������� ������ (E2EE): " << decrypted_text << '\n';

        break;
    }
    case 'h':
    {
        // ����������� ������
        std::string hashed_text = hash_data(input_text);
        std::cout << "���-�������� ��� ������� ������: " << hashed_text << '\n';

        // �������� ������������ ���-�������� �������� ������
        std::string expected_hash;
        std::cout << "������� ��������� ���-��������: ";
        std::cin >> expected_hash;

        if (verify_hash(input_text, expected_hash))
            std::cout << "���-�������� ������������� �������� ������." << '\n';
        else
            std::cout << "���-�������� �� ������������� �������� ������." << '\n';

        break;
    }
    default:
        std::cout << "�������� ����� ����������. ����� �� ���������." << std::endl;
    }

    std::cout << "������� ����� ������� ��� ������...";
    _getch();

	return 0;
}