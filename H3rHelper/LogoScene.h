#pragma once
#include <QtWidgets>

/* 重写可以点击的 GraphicsScene */
class LogoScene : public QGraphicsScene
{
	Q_OBJECT

public:
	/* 重写鼠标点击事件 */
	void mousePressEvent(QGraphicsSceneMouseEvent *event);
};
