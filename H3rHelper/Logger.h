#pragma once
#include <QtWidgets>

/* ��־�ȼ� */
#define LEVEL_INFO 0
#define LEVEL_WARNING 1
#define LEVEL_ERROR 2

/* ��־��¼�� */
void Logger(QTextBrowser * b, int level, QString text);
