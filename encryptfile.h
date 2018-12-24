#ifndef ENCRYPTFILE_H
#define ENCRYPTFILE_H

#endif // ENCRYPTFILE_H

#include <QString>      // для работы со строками Qt
#include <QMessageBox>

#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <fstream>

#define BLOCK_LENGTH 4096   // максимальная длинна блока для шифрования и расшифрования

bool encrypt_file(
        QString address,    // адрес шифруемого файла
        QString password,   // фраза для вектора инициализации
        HCRYPTKEY hSessionKey   //дискриптор ключа
        );
