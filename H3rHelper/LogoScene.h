#pragma once
#include <QtWidgets>

/* ��д���Ե���� GraphicsScene */
class LogoScene : public QGraphicsScene
{
	Q_OBJECT

public:
	/* ��д������¼� */
	void mousePressEvent(QGraphicsSceneMouseEvent *event);
};
