#include "DecryptFile.h"

bool decrypt_file(QString address, QString password, HCRYPTKEY hSessionKey){

    FILE *content=NULL;              // Исходный файл
    FILE *Decrypt=NULL;              // Зашифрованный файл

    BYTE pbContent[BLOCK_LENGTH] = { 0 };	// Указатель на содержимое исходного файла
    DWORD cbContent = 0;					// Длина содержимого
    DWORD bufLen = sizeof(pbContent);

    if(password == ""){
        password = "default";
    }


    //Задаем вектор инициализкации
    if(!CryptSetKeyParam(hSessionKey,KP_IV, (BYTE *)password.toLocal8Bit().data(),0))
    {
        QMessageBox::critical(NULL,QObject::tr("Ошибка"), "Ошибка установки вектора инициализации.");
        return 1;
    }

    content = fopen(address.toLocal8Bit().data(), "r");
    if (!content){
        QMessageBox::critical(NULL,QObject::tr("Ошибка"), "Ошибка открытия файла для дешифрования.");
        return 1;
    }

    Decrypt = fopen((address + ".decrypt").toLocal8Bit().data(), "wb");
    if (!Decrypt){
        QMessageBox::critical(NULL,QObject::tr("Ошибка"), "Ошибка открытия файла для результата дешифрования.");
        return 1;
    }

    do
    {
        memset(pbContent, 0, sizeof(pbContent));
        cbContent = (DWORD)fread(pbContent, 1, BLOCK_LENGTH , content);
        pbContent[cbContent] = '\0';

        if (cbContent)
        {
            BOOL bFinal = feof(content);
            // Дешифроние прочитанного блока на сессионном ключе.
            if (CryptDecrypt(hSessionKey, 0, bFinal, 0, (BYTE*)pbContent, &cbContent))
            {
                // Запись дешифрованного блока в файл.
                if (!fwrite(pbContent, 1, cbContent, Decrypt))
                {
                    QMessageBox::critical(NULL,QObject::tr("Ошибка"), "Ошибка записи дешифрованного блока.");
                    fclose(Decrypt);
                    fclose(content);
                    return 1;
                }
            }
            else
            {
                QMessageBox::critical(NULL,QObject::tr("Ошибка"), "Ошибка при дешифровании блока.");
                fclose(Decrypt);
                fclose(content);
                return 1;
            }
        }
        else
        {
            QMessageBox::critical(NULL,QObject::tr("Ошибка"), "Ошибка чтения блока из файла.");
            fclose(Decrypt);
            fclose(content);
            return 1;
        }
    } while (!feof(content));

    fclose(Decrypt);
    fclose(content);

    return 0;
}
