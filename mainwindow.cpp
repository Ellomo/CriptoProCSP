#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "QDebug"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    //При включении программы инициализируем ключ

    // Получение дескриптора криптопровайдера
    if(!CryptAcquireContext(
                &hProvForSessionKey,    // Дискриптор для сессионного ключа
                NULL,                   // Без контейнера
                NULL,                   // По умолчанию
                PROV_GOST_2012_256,     // Провайдер
                CRYPT_VERIFYCONTEXT))   // мод для работы с данными
    {
        QMessageBox::critical(NULL,QObject::tr("Ошибка"), "Ошибка получения дискриптора CSP для шифрования.");
    }
    else{
        // Генерация ключа
        if (!CryptGenKey(hProvForSessionKey, CALG_G28147,  CRYPT_EXPORTABLE, &hSessionKey))
        {
            QMessageBox::critical(NULL,QObject::tr("Ошибка"), "Ошибка генерации сессионного ключа.");
        }
    }
}

MainWindow::~MainWindow()
{
    delete ui;
    CryptDestroyKey(hSessionKey);
}

void MainWindow::on_Use_Conteiner_clicked()
{
    BYTE pszUserName[MAX_CONTAINER_NAME_LEN];   // Буфер для хранения имени  ключевого контейнера.
    DWORD dwUserNameLen;                        // Длина буфера.

    // Установка контекста
    if(CryptAcquireContextW(
                &hProvForSign,                                          // Дескриптор CSP
                (const wchar_t*) ui->Name_Conteiner->text().utf16(),    // Имя контейнера
                NULL,                                                   // Использование провайдера по умолчанию
                PROV_GOST_2012_256,                                     // Тип провайдера
                0))                                                     // Значения флагов
    {
        // Получение ключевой пары
        if(CryptGetUserKey(
                    hProvForSign,   // Дескриптор CSP
                    AT_SIGNATURE,   // Спецификация ключа
                    &hKey))         // Дескриптор ключа
        {
            ui->Used_Name_Conteiner->setText(ui->Name_Conteiner->text());
        }
        else
        {
            QMessageBox::critical(NULL,QObject::tr("Ошибка"), "Дискриптор на ключевую пару не получен.");
        }
    }
    else
    {
        // Создание нового контейнера.
        if(!CryptAcquireContextW(
                    &hProvForSign,
                    (const wchar_t*) ui->Name_Conteiner->text().utf16(),
                    NULL,
                    PROV_GOST_2012_256,
                    CRYPT_NEWKEYSET))
        {
            QMessageBox::critical(NULL,QObject::tr("Ошибка"), "Контейнер не создан.");
        }
        else
        {
            // Генерация ключевой пары
            if(!CryptGenKey(
                        hProvForSign,
                        AT_SIGNATURE,
                        CRYPT_EXPORTABLE,
                        &hKey))                         // Дескриптор ключа
            {
                QMessageBox::critical(NULL,QObject::tr("Ошибка"), "Ключевая пара не создана.");
            }
            else
            {
                ui->Used_Name_Conteiner->setText(ui->Name_Conteiner->text());
            }
        }
    }
}

void MainWindow::on_Select_Address_clicked()
{
    ui->Address->setText(QFileDialog::getOpenFileName(0, "Выбор файла", "C:/Users/LMNV/Desktop", 0));   // Переписываем значение виджета адресом папки выбранной в ходе диалога
}

void MainWindow::on_Sing_clicked()
{

    // Создание объекта функции хеширования.
    if(!CryptCreateHash(
                hProvForSign,
                CALG_GR3411_2012_256,
                0,
                0,
                &hHash))
    {
        QMessageBox::critical(NULL,QObject::tr("Ошибка"), "При создании объекта хеш функции возникла ошибка.");
    }

    //Открываем файл
    std::ifstream file(ui->Address->text().toLocal8Bit().data());

    //Получаем длинну файла
    file.seekg( 0, std::ios::end );
    size_t length = file.tellg();

    BYTE *pbBuffer= new BYTE[length];

    file.seekg(0, std::ios::beg);

    file.read((char *)pbBuffer, length);

    file.close();

    DWORD dwBufferLen = (DWORD)(strlen((char *)pbBuffer)+1);


    // Вычисление криптографического хеша буфера.
    if(!CryptHashData(
                hHash,
                pbBuffer,
                dwBufferLen,
                0))
    {
        QMessageBox::critical(NULL,QObject::tr("Ошибка"), "При вычислении хэша содержимого файла произошла ошибка.");
    }

    // Определение размера подписи и распределение памяти.
    DWORD dwSigLen = 0;
    if(!CryptSignHash(
                hHash,
                AT_SIGNATURE,
                NULL,
                0,
                NULL,
                &dwSigLen))
    {
        QMessageBox::critical(NULL,QObject::tr("Ошибка"), "При вычислении размера буфера для подписи произошла ошибка.");
    }

    // Распределение памяти под буфер подписи.
    BYTE * pbSignature = (BYTE *)malloc(dwSigLen);
    if(!pbSignature)
        QMessageBox::critical(NULL,QObject::tr("Ошибка"), "При выделении памяти для подписи ошибка.");

    // Подпись объекта функции хеширования.
    if(!CryptSignHash(
                hHash,
                AT_SIGNATURE,
                NULL,
                0,
                pbSignature,
                &dwSigLen))
    {
        QMessageBox::critical(NULL,QObject::tr("Ошибка"), "При подписании хэша файла произошла ошибка.");
    }

    // Запись подписи в файл
    FILE * signature;
    if(!(signature = fopen((ui->Address->text() + ".signature").toLocal8Bit().data(), "w+b")))
        QMessageBox::critical(NULL,QObject::tr("Ошибка"), "При записи подписи в файл произошла ошибка.");

    fwrite(pbSignature, 1, dwSigLen, signature);
    fclose(signature);

    // Узнаем длинну под ключ
    DWORD dwBlobLen;
    if(!CryptExportKey(
                hKey,
                0,
                PUBLICKEYBLOB,
                0,
                NULL,
                &dwBlobLen))
    {
        QMessageBox::critical(NULL,QObject::tr("Ошибка"), "При вычислении длинны открытого ключа произошла ошибка.");
    }

    // Распределение памяти под pbKeyBlob.
    pbKeyBlob = (BYTE*)malloc(dwBlobLen);
    if(!pbKeyBlob)
        QMessageBox::critical(NULL,QObject::tr("Ошибка"), "При выделении памяти под открытый ключ произошла ошибка.");

    // Сам экспорт в ключевой BLOB.
    if(!CryptExportKey(
                hKey,
                0,
                PUBLICKEYBLOB,
                0,
                pbKeyBlob,
                &dwBlobLen))
    {
        QMessageBox::critical(NULL,QObject::tr("Ошибка"), "При экспортировании открытого ключа произошла ошибка.");
    }

    // Запись открытого ключа в файл
    FILE * publickey;
    if(!(publickey = fopen((ui->Address->text() + ".signature.publickey").toLocal8Bit().data(), "w+b")))
        QMessageBox::critical(NULL,QObject::tr("Ошибка"), "При записи открытого ключа в файл произошла ошибка.");

    fwrite(pbKeyBlob, 1, dwBlobLen, publickey);
    fclose(publickey);
    qDebug()<<dwBlobLen;
    // Уничтожение объекта функции хеширования.
    if(hHash)
        CryptDestroyHash(hHash);

}

void MainWindow::on_Check_Sing_clicked()
{
    // Создание объекта функции хеширования.
    if(!CryptCreateHash(
                hProvForSign,
                CALG_GR3411_2012_256,
                0,
                0,
                &hHash))
    {
        QMessageBox::critical(NULL,QObject::tr("Ошибка"), "При создании объекта хеш функции возникла ошибка.");
    }

    //Открываем файл
    std::ifstream file(ui->Address->text().toLocal8Bit().data());

    //Получаем длинну файла
    file.seekg( 0, std::ios::end );
    size_t length = file.tellg();

    BYTE *pbBuffer= new BYTE[length];

    file.seekg(0, std::ios::beg);

    file.read((char *)pbBuffer, length);

    file.close();

    DWORD dwBufferLen = (DWORD)(strlen((char *)pbBuffer)+1);

    // Вычисление криптографического хеша буфера.
    if(!CryptHashData(
                hHash,
                pbBuffer,
                dwBufferLen,
                0))
    {
        QMessageBox::critical(NULL,QObject::tr("Ошибка"), "При вычислении хэша содержимого файла произошла ошибка.");
    }

    //Открываем файл подписи
    std::ifstream signature_file((ui->Address->text() + ".signature").toLocal8Bit().data());
    DWORD dwSigLen = 64;
    BYTE * pbSignature = (BYTE *)malloc(dwSigLen);
    if(!pbSignature)
        QMessageBox::critical(NULL,QObject::tr("Ошибка"), "При выделении памяти для подписи ошибка.");
    signature_file.read((char*)pbSignature,(size_t)dwSigLen);

    signature_file.close();

    //Открываем файл открытого ключа
    std::ifstream publickey_file((ui->Address->text() + ".signature.publickey").toLocal8Bit().data());
    DWORD dwBlobLen = 101;
    BYTE * pbKeyBlob = (BYTE *)malloc(dwBlobLen);
    if(!pbKeyBlob)
        QMessageBox::critical(NULL,QObject::tr("Ошибка"), "При выделении памяти для открытого ключа произошла ошибка.");
    publickey_file.read((char*)pbKeyBlob,(size_t)dwBlobLen);

    publickey_file.close();


    // Получение откытого ключа пользователя, который создал цифровую подпись,
    // и импортирование его в CSP с помощью функции CryptImportKey. Она
    // возвращает дескриптор открытого ключа в hPubKey.
    if(!CryptImportKey(
                hProvForSign,
                pbKeyBlob,
                dwBlobLen,
                0,
                0,
                &hPubKey))
    {
        QMessageBox::critical(NULL,QObject::tr("Ошибка"), "При импортировании открытого ключа произошла ошибка.");
    }

    // Проверка цифровой подписи.
    if(!CryptVerifySignature(
                hHash,
                pbSignature,
                dwSigLen,
                hPubKey,
                NULL,
                0))
    {
        QMessageBox::critical(NULL,QObject::tr("Ошибка"), "При проверке подписи произошла ошибка.");
    }
    else{
        QMessageBox::information(NULL,QObject::tr("Подпись верна"), "Подпись прошла проверку.");
    }
    if(hHash)
        CryptDestroyHash(hHash);

}


void MainWindow::on_Encrypt_clicked()
{
    // Вызов функции шифрования
    if(!encrypt_file(
                ui->Address->text(),
                ui->Password->text(),
                hSessionKey))
    {
        QMessageBox::information(NULL,QObject::tr("Шифрование успешено"), "Шифрование файла прошло успешно.");
    }
}

void MainWindow::on_Decrypt_clicked()
{
    // Вызов функции дешифрования
    if(!decrypt_file(
                ui->Address->text(),
                ui->Password->text(),
                hSessionKey))
    {
        QMessageBox::information(NULL,QObject::tr("Дешифрование успешено"), "Дешифрование файла прошло успешно.");
    }
}
