#ifndef DECRYPTFILE_H
#define DECRYPTFILE_H

#endif // DECRYPTFILE_H

#include <QString>
#include <QMessageBox>

#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <fstream>

#define BLOCK_LENGTH 4096 // максимальная длинна блока для шифрования и расшифрования

// Функция расшифрования файла аналогична функции зашифрования
// с отличием в том, что весто CryptEncrypt используется CryptDecrypt
bool decrypt_file(QString address, QString password, HCRYPTKEY hSessionKey);
