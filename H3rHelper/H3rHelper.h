#pragma once

#include <QtWidgets/QMainWindow>
#include <QNetworkConfigurationManager> 
#include "ui_H3rHelper.h"
#include "LogoScene.h"

class H3rHelper : public QMainWindow
{
	Q_OBJECT

public:
	H3rHelper(QWidget *parent = Q_NULLPTR);
	void sRunDetect();
	void imcDetect();
	void imcLogout(int type);
	bool imcConnected(int type);
	void sRunGetInfo(int type);
	void sRunLogin(int type);
	void sRunLogout(int type);
	void imcAuthorize(int type);
	
public slots:
	void on_activatedSysTrayIcon(QSystemTrayIcon::ActivationReason reason);

private:
	Ui::H3rHelperClass ui;
};
