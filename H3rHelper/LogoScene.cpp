#include "stdafx.h"
#include "LogoScene.h"

/* 重写鼠标点击事件 */
void LogoScene::mousePressEvent(QGraphicsSceneMouseEvent *event) {
	QString homepage = "http://www.nwpu.edu.cn";
	QDesktopServices::openUrl(QUrl(homepage));
}
