#pragma once
#include <QtWidgets>

/* 日志等级 */
#define LEVEL_INFO 0
#define LEVEL_WARNING 1
#define LEVEL_ERROR 2

/* 日志记录器 */
void Logger(QTextBrowser * b, int level, QString text);
