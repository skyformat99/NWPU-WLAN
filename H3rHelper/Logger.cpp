#include "Logger.h"
#include "stdafx.h"

/* ÈÕÖ¾¼ÇÂ¼Æ÷ */
void Logger(QTextBrowser * b, int level, QString text)
{
	QDateTime currentDateTime = QDateTime::currentDateTime();
	QString currentTime = currentDateTime.toString("hh:mm:ss");

	switch (level) {
	case 2:
		text = "<font color=\"red\">" + text + "</font>";
	case 1:
		text = "<b>" + text + "</b>";
	case 0:
		text = "" + text + "";
	}

	b->append("<span>[" + currentTime + "] " + text + "</span>");
	b->moveCursor(QTextCursor::End);
}
