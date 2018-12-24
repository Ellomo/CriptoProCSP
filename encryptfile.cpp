#include "EncryptFile.h"

bool encrypt_file(QString address, QString password, HCRYPTKEY hSessionKey){


    FILE *content=NULL;              // Исходный файл
    FILE *Encrypt=NULL;              // Зашифрованный файл

    BYTE pbContent[BLOCK_LENGTH] = { 0 };	// Указатель на содержимое исходного файла
    DWORD cbContent = 0;					// Длина содержимого
    DWORD bufLen = sizeof(pbContent);       // Размер буфера

    if(password == ""){ // если фраза не указана, то задаем ей значение по умолчанию отличное от 0
        //это фажно, так как при передаче 0 в качестве аргумента, IV будет случайным
        password = "default";
    }

    //Задаем вектор инициализкации
    if(!CryptSetKeyParam(hSessionKey,KP_IV, (BYTE *)password.toLocal8Bit().data(),0))
    {
        QMessageBox::critical(NULL,QObject::tr("Ошибка"), "Ошибка установки вектора инициализации.");
        return 1;
    }

    //Открываем файл для шифрования
    content = fopen(address.toLocal8Bit().data(), "r");
    if (!content){
        QMessageBox::critical(NULL,QObject::tr("Ошибка"), "Ошибка открытия файла для шифрования.");
        return 1;
    }

    //Открываем/создаем файл для результата
    Encrypt = fopen((address + ".encrypt").toLocal8Bit().data(), "wb");
    if (!Encrypt){
        QMessageBox::critical(NULL,QObject::tr("Ошибка"), "Ошибка открытия файла для результата шифрования.");
        return 1;
    }

    do
    {
        // Берем блок для шифрования
        memset(pbContent, 0, sizeof(pbContent));
        cbContent = (DWORD)fread(pbContent, 1, BLOCK_LENGTH , content);
        pbContent[cbContent] = '\0';

        if (cbContent)
        {
            // Проверяем последний ли это блок
            BOOL bFinal = feof(content);
            // Зашифрованние прочитанного блока на сессионном ключе.
            if (CryptEncrypt(hSessionKey, 0, bFinal, 0, (BYTE*)pbContent, &cbContent, bufLen))
            {
                // Запись зашифрованного блока в файл.
                if (!fwrite(pbContent, 1, cbContent, Encrypt))
                {
                    QMessageBox::critical(NULL,QObject::tr("Ошибка"), "Ошибка записи зашифрованного блока.");
                    fclose(Encrypt);
                    fclose(content);
                    return 1;
                }
            }
            else
            {
                QMessageBox::critical(NULL,QObject::tr("Ошибка"), "Ошибка при шифровании блока.");
                fclose(Encrypt);
                fclose(content);
                return 1;
            }
        }
        else
        {
            QMessageBox::critical(NULL,QObject::tr("Ошибка"), "Ошибка чтения блока из файла.");
            fclose(Encrypt);
            fclose(content);
            return 1;
        }
    } while (!feof(content));   // Выполняем пока не дойдем до конца файла

    fclose(Encrypt);
    fclose(content);

    return 0;

}
