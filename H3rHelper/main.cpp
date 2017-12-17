#include "stdafx.h"
#include "H3rHelper.h"
#include <QtWidgets/QApplication>
#include <QtNetwork>
#include <QUrl>
#include <signal.h>

void SignalHandler(int signal)
{
	printf("Signal %d", signal);
	throw "!Access Violation!";
}

int main(int argc, char *argv[])
{
	/* 启用 VA 错误的捕获 */
	typedef void(*SignalHandlerPointer)(int);
	SignalHandlerPointer previousHandler;
	previousHandler = signal(SIGSEGV, SignalHandler);

	QApplication a(argc, argv);

	/* 设置界面字体 */
	QFont font;
	font.setFamily("Microsoft Yahei");
	a.setFont(font);

	H3rHelper w;
	w.show();

	return a.exec();
}
