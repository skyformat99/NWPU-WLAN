#include "stdafx.h"
#include "LogoScene.h"

/* ��д������¼� */
void LogoScene::mousePressEvent(QGraphicsSceneMouseEvent *event) {
	QString homepage = "http://www.nwpu.edu.cn";
	QDesktopServices::openUrl(QUrl(homepage));
}
