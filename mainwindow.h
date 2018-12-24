#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QMessageBox>  // для использования сообщений
#include <QFileDialog>  // для использования диалогов поиска файлов

#include <stdio.h>      // для использования потоков
#include <windows.h>    // для использования типов переменних msdn
#include <wincrypt.h>   // криптографическая библиотека
#include <fstream>      // для работы с файлами

#include "EncryptFile.h"    // заголовочный файл функции шифрования
#include "DecryptFile.h"    // заголовочный файл функции рашифрования

#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING) // не знаю что это, но в примерах КриптоПро было / наверное для ставбильной работы

#define MAX_CONTAINER_NAME_LEN 260  // максимальная длинна имени ключевого контейнера

// Из-за того, что cpcspi.dll не подключается нормально сами объявим типы криптопровайдеров Крипто Про основываясь на записях реестров
#define PROV_GOST_2001_DH 75    // провайдер использует алгоритм ГОСТ Р 34.10-2001
#define PROV_GOST_2012_256 80   // провайдер использует алгоритм ГОСТ Р 34.10-2012 длины 256 бит (длина открытого ключа 512 бит)
#define PROV_GOST_2012_512 81   // провайдер использует алгоритм ГОСТ Р 34.10-2012 длины 512 бит (длина открытого ключа 1024 бит)

//По аналогичной причине
#define CALG_GR3411_2012_256 32801  // алгоритм для хэширования
#define CALG_G28147 26142           // алгоритм шифрования


namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:

    HCRYPTPROV hProvForSign;        // Дескриптор CSP для подписи.
    HCRYPTPROV hProvForSessionKey;  // Дескриптор CSP для шифрования.

    HCRYPTKEY hKey;                 // Дескриптор ключеваой пары подписи
    HCRYPTKEY hPubKey;              // Дескриптор открытого ключа подписи
    HCRYPTKEY hSessionKey;          // Дескриптор сессионного ключа


    HCRYPTHASH hHash;               // Дискриптор Хэша

    BYTE *pbKeyBlob;// экспортированный открытый ключ

    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_Use_Conteiner_clicked();    // слот для выбора или создания контейнера

    void on_Select_Address_clicked();   // слот выбора файла

    void on_Sing_clicked();             // слот подписания файла

    void on_Check_Sing_clicked();       // слот проверки подписи файла

    void on_Encrypt_clicked();          // слот шифрования файла

    void on_Decrypt_clicked();          // слот расшифрования файла

private:
    Ui::MainWindow *ui;
};

#endif // MAINWINDOW_H
