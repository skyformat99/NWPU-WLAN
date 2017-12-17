#include "stdafx.h"
#include "H3rHelper.h"
#include "Logger.h"
#include "IMCPortal.h"

int status = 0;
QTimer *timer; // 心跳定时器
QTimer *timeout; // 探测超时（别的不许用）
QNetworkAccessManager *networkManager; // 网络管理器
QSystemTrayIcon * mSysTrayIcon; // 托盘图标
/* 网络响应*/
QNetworkReply *r; // 检测
QNetworkReply *ro; // 下线
QNetworkReply *reply; // 认证
QString last = ""; // 最后执行

H3rHelper::H3rHelper(QWidget *parent)
	: QMainWindow(parent)
{
	ui.setupUi(this);
	/* 初始化窗口 */
	setFixedSize(
		this->geometry().width(),
		this->geometry().height()
	);
	setWindowTitle(QStringLiteral("瓜大无线小助手"));

	/* 加载学校横标 */
	QImage * logo = new QImage(":/H3rHelper/Resources/logo.bmp");
	LogoScene *scene = new LogoScene;
	scene->addPixmap(QPixmap::fromImage(*logo));
	ui.logo->setScene(scene);
	ui.logo->setCursor(QCursor(Qt::PointingHandCursor));
	ui.logo->setStyleSheet("QGraphicsView { border-style: none; }");

	/* 载入保存的信息 */
	QSettings settings(
		"HKEY_CURRENT_USER\\Software\\H3rHelper",
		QSettings::NativeFormat
	);
	QString sno = settings.value("username", "").toString();
	QString code = settings.value("password", "").toString();
	if (sno != "" && code != "") {
		ui.line_sno->setText(sno);
		ui.line_code->setText(code);
	}

	/* 认证服务改动时的选项切换 */
	connect(ui.combo_service, static_cast<void (QComboBox::*)(const QString &)>(&QComboBox::currentIndexChanged), [this]() {
		int current = ui.combo_service->currentIndex();
		if (current >= TYPE_LIB) {
			ui.widget_action->setDisabled(true);
			ui.button_toggle->setText(QStringLiteral("连接"));
			ui.button_info->setDisabled(true);
		}
		else {
			ui.widget_action->setDisabled(false);
			ui.button_toggle->setText(QStringLiteral("认证"));
			ui.button_info->setDisabled(false);
		}
	});

	/* 清空按钮 */
	connect(ui.button_clear, &QPushButton::clicked, [this]() {
		auto b = QMessageBox::question(
			NULL,
			QStringLiteral("清空日志"),
			QStringLiteral("您确定？"),
			QMessageBox::Yes | QMessageBox::No, QMessageBox::Yes
		);
		if (b == QMessageBox::Yes) {
			ui.text_log->clear();
		}
	});

	/* 初始化托盘图标 */
	QSystemTrayIcon * mSysTrayIcon = new QSystemTrayIcon(this);
	QIcon icon = QIcon(":/H3rHelper/Resources/icon.png");
	mSysTrayIcon->setIcon(icon);
	mSysTrayIcon->setToolTip(QStringLiteral("瓜大无线小助手"));
	connect(
		mSysTrayIcon,
		SIGNAL(activated(QSystemTrayIcon::ActivationReason)),
		this,
		SLOT(on_activatedSysTrayIcon(QSystemTrayIcon::ActivationReason))
	);
	mSysTrayIcon->show();
	/* 隐藏到托盘按钮 */
	connect(ui.button_hide, &QPushButton::clicked, [=]() {
		this->hide();
	});

	/* 自助服务按钮 */
	connect(ui.button_self, &QPushButton::clicked, [this]() {
		QString self = "http://zizhu.nwpu.edu.cn";
		QDesktopServices::openUrl(QUrl(self));
	});

	/* 初始化切换按钮 */
	ui.button_toggle->setStyleSheet("QPushButton { font-weight: bold; }");
	ui.button_toggle->setText(QStringLiteral("连接"));

	/* 切换按钮功能 */
	connect(ui.button_toggle, &QPushButton::clicked, [this]() {
		/* 获取输入信息 */
		QString sno = ui.line_sno->text();
		QString code = ui.line_code->text();

		/* 存储输入信息 */
		QSettings settings(
			"HKEY_CURRENT_USER\\Software\\H3rHelper",
			QSettings::NativeFormat
		);
		settings.setValue("username", sno);
		settings.setValue("password", code);

		/* 判断输入是否为空 */
		if (sno == "" || code == "") {
			QMessageBox::critical(
				NULL,
				QStringLiteral("错误"),
				QStringLiteral("学号和密码不得为空！")
			);
			Logger(ui.text_log, LEVEL_ERROR, QStringLiteral("学号和密码不得为空！"));
			return;
		}

		/* 读取目标服务 */
		int i = ui.combo_service->currentIndex();
		if (i || ui.button_toggle->text() == QStringLiteral("取消")) {
			auto op = ui.button_toggle->text();
			if (op == QStringLiteral("连接")) {
				if (imcConnected(i)) {
					/* 禁用表单 */
					ui.button_toggle->setText(QStringLiteral("取消"));
					ui.line_code->setDisabled(true);
					ui.line_sno->setDisabled(true);
					ui.button_detect->setDisabled(true);
					ui.combo_service->setDisabled(true);

					imcAuthorize(i);
				}
			}
			else if (op == QStringLiteral("下线")) {
				/* 禁用表单 */
				ui.button_toggle->setText(QStringLiteral("取消"));
				ui.line_code->setDisabled(true);
				ui.line_sno->setDisabled(true);
				ui.button_detect->setDisabled(true);
				ui.combo_service->setDisabled(true);

				imcLogout(i);
			}
			else if (op == QStringLiteral("取消")) {
				/* 取消操作 */
				if (last == "ro") {
					try {
						ro->abort();
						ro->deleteLater();
						timer->stop();
					}
					catch (char *e) { }
				}
				if (last == "reply") {
					try {
						reply->abort();
						reply->deleteLater();
						timer->stop();
					}
					catch (char *e) { }
				}

				/* 恢复表单 */
				if (ui.combo_service->currentIndex() <= TYPE_WLAN_S) {
					ui.button_toggle->setText(QStringLiteral("认证"));
				}
				else {
					ui.button_toggle->setText(QStringLiteral("连接"));
				}
				ui.line_code->setDisabled(false);
				ui.line_sno->setDisabled(false);
				ui.button_detect->setDisabled(false);
				ui.combo_service->setDisabled(false);
				Logger(ui.text_log, LEVEL_WARNING, QStringLiteral("操作取消，服务停止"));
			}
			else { // 认证
				if (imcConnected(i)) {
					/* 禁用表单 */
					ui.button_toggle->setText(QStringLiteral("取消"));
					ui.line_code->setDisabled(true);
					ui.line_sno->setDisabled(true);
					ui.button_detect->setDisabled(true);
					ui.combo_service->setDisabled(true);

					if (ui.radio_login->isChecked()) { sRunLogin(i); }
					else { sRunLogout(i); }
				}
			}
		}
		else {
			QMessageBox::critical(
				NULL,
				QStringLiteral("错误"),
				QStringLiteral("请选择或自动检测目标服务！")
			);
			Logger(ui.text_log, LEVEL_ERROR, QStringLiteral("请选择或自动检测目标服务！"));
		}
	});

	/* 初始化用户状态按钮 */
	connect(ui.button_info, &QPushButton::clicked, [this]() {
		if (ui.combo_service->currentIndex() && ui.combo_service->currentIndex() <= TYPE_WLAN_S) {
			int i = ui.combo_service->currentIndex();

			if (imcConnected(i)) {
				/* 禁用表单 */
				ui.button_toggle->setText(QStringLiteral("取消"));
				ui.line_code->setDisabled(true);
				ui.line_sno->setDisabled(true);
				ui.button_detect->setDisabled(true);
				ui.combo_service->setDisabled(true);

				sRunGetInfo(i);
			}
		}
		else {
			QMessageBox message(QMessageBox::Information, QStringLiteral("提示"), QStringLiteral("仅支持深澜认证\n请选择深澜的服务后再试"));
			message.exec();
		}
	});

	/* 初始化识别按钮 */
	connect(ui.button_detect, &QPushButton::clicked, [this]() {
		/* 禁用表单 */
		ui.combo_service->setDisabled(true);
		ui.button_detect->setDisabled(true);
		ui.button_toggle->setDisabled(true);

		/* 提示用户在两种系统中选择 */
		QMessageBox messageBox(QMessageBox::Question,
			QStringLiteral("认证系统"),
			QStringLiteral("请先选择当前使用的认证系统\n提示：华三即为老版锐捷"),
			QMessageBox::Yes | QMessageBox::No,
			this);
		messageBox.setButtonText(QMessageBox::Yes, QStringLiteral("华三"));
		messageBox.setButtonText(QMessageBox::No, QStringLiteral("深澜"));
		auto b = messageBox.exec();
		if (b == QMessageBox::No) {
			sRunDetect();
		}
		else {
			imcDetect();
		}
	});

	/* 关于对话框 */
	connect(ui.button_about, &QPushButton::clicked, [this]() {
		QMessageBox message(
			QMessageBox::NoIcon,
			QStringLiteral("关于程序"),
			QStringLiteral(
				"瓜大无线小助手 1.0β<br /><br />"
				"2017 版权所有，翻版不究<br /><br />"
				"本程序仅供学习交流之用，严禁用于任何非法或商业目的，违者一切后果自行承担。"
			)
		);
		message.setIconPixmap(QPixmap(":/H3rHelper/Resources/icon.png"));
		message.exec();
	});

	/* 初始化网络管理器 */
	networkManager = new QNetworkAccessManager();
	/* 设置定时器 */
	timeout = new QTimer();
	timeout->setInterval(8000);
	timeout->setSingleShot(true);
	connect(timeout, &QTimer::timeout, [this]() {
		if (r->isRunning()) {
			r->abort();
		}
		r->deleteLater();

		/* 恢复表单 */
		ui.combo_service->setDisabled(false);
		ui.button_detect->setDisabled(false);
		ui.button_toggle->setDisabled(false);

		/* 认定 137 不可用 */
		Logger(ui.text_log, LEVEL_WARNING, QStringLiteral("137不可访问，自动选为138"));
		Logger(ui.text_log, LEVEL_INFO, QStringLiteral("建议多试几次以确保检测的准确性"));
		ui.combo_service->setCurrentIndex(TYPE_138);
	});
	timer = new QTimer();
	timer->setInterval(30000); // 心跳周期为30秒
	connect(timer, &QTimer::timeout, [this]() {
		imcAuthorize(ui.combo_service->currentIndex());
	});

	/* 初始化完成日志 */
	Logger(ui.text_log, LEVEL_INFO, QStringLiteral("程序已启动"));
}

/* sRun 识别服务 */
void H3rHelper::sRunDetect() {
	QNetworkConfigurationManager ncm;
	auto nc = ncm.allConfigurations();
	int flag = 0;
	for (auto &x : nc) {
		if (x.name() == "NWPU-WLAN" && x.state() == QNetworkConfiguration::Active) {
			flag = TYPE_WLAN_S;
			break;
		}
		else if (x.name() == "NWPU-LIB" && x.state() == QNetworkConfiguration::Active) {
			flag = TYPE_LIB_S;
			break;
		}
	}
	ui.combo_service->setCurrentIndex(flag);
	if (!flag) {
		Logger(ui.text_log, LEVEL_WARNING, QStringLiteral("未检测到接入学校网络"));
	}

	/* 恢复表单 */
	ui.combo_service->setDisabled(false);
	ui.button_detect->setDisabled(false);
	ui.button_toggle->setDisabled(false);
}

/* IMC 识别服务 */
void H3rHelper::imcDetect() {
	/* 假定服务是 137 */
	QUrl serviceUrl = QUrl(Service[TYPE_137] + "pws?t=li");
	QUrlQuery postData;
	postData.addQueryItem("userName", "helper");
	postData.addQueryItem("userPwd", "aGVscGVy");

	QNetworkRequest request(serviceUrl);
	request.setHeader(
		QNetworkRequest::ContentTypeHeader,
		"application/x-www-form-urlencoded"
	);
	request.setRawHeader("Accept", "text/plain, */*; q=0.01");
	request.setRawHeader("Accept-Language", "zh-CN,zh;q=0.8");
	request.setRawHeader("Accept-Encoding", "gzip, deflate");

	r = networkManager->post(request, postData.toString(QUrl::FullyEncoded).toUtf8());
	timeout->start();
	last = "r";

	connect(r, &QNetworkReply::finished, [=] {
		timeout->stop();
		/* 恢复表单 */
		ui.combo_service->setDisabled(false);
		ui.button_detect->setDisabled(false);
		ui.button_toggle->setDisabled(false);

		if (r->error() != QNetworkReply::NoError) {
			ui.combo_service->setCurrentIndex(TYPE_138);
		}

		QByteArray res = r->readAll();
		QString data = QByteArray::fromBase64(res);
		data = QUrl(data).fromPercentEncoding(data.toUtf8());
		QJsonDocument jsonResponse = QJsonDocument::fromJson(data.toUtf8());
		QJsonObject jsonObject = jsonResponse.object();
		if (jsonObject.take("errorNumber") == "7" &&
			jsonObject.take("portServErrorCode") == "124")
		{
			/* 向设备发送请求超时 */
			ui.combo_service->setCurrentIndex(TYPE_138);

		}
		else {
			QNetworkConfigurationManager ncm;
			auto nc = ncm.allConfigurations();
			bool flag = false;
			for (auto &x : nc) {
				if (x.name() == "NWPU-WLAN" && x.state() == QNetworkConfiguration::Active) {
					ui.combo_service->setCurrentIndex(TYPE_137);
					flag = true;
				}
			}
			if (!flag) { ui.combo_service->setCurrentIndex(TYPE_LIB); }
		}

		r->deleteLater(); /* 释放内存 */
	});
}

/* 网络下线 */
void H3rHelper::imcLogout(int type) {
	QUrl serviceUrl = QUrl(Service[type] + "pws?t=lo");

	QNetworkRequest request(serviceUrl);
	request.setRawHeader("Accept", "text/plain, */*; q=0.01");
	request.setRawHeader("Accept-Language", "zh-CN,zh;q=0.8");
	request.setRawHeader("Accept-Encoding", "gzip, deflate");
	
	ro = networkManager->get(request);
	last = "ro";

	connect(ro, &QNetworkReply::finished, [=] {
		if (ro == nullptr) { return; } // 操作被清空
		if (ro->error() == QNetworkReply::NoError) {
			QByteArray res = ro->readAll();
			QString data = QByteArray::fromBase64(res);
			data = QUrl(data).fromPercentEncoding(data.toUtf8());
			QJsonDocument jsonResponse = QJsonDocument::fromJson(data.toUtf8());
			QJsonObject jsonObject = jsonResponse.object();
			if (jsonObject.contains("portServErrorCodeDesc")) {
				/* 用户已经下线 */
				Logger(ui.text_log, LEVEL_WARNING, QStringLiteral("警告：") + jsonObject.take("portServErrorCodeDesc").toString());
			}
			else {
				Logger(ui.text_log, LEVEL_INFO, QStringLiteral("下线成功！"));
			}
		}
		else {
			ui.text_log, LEVEL_WARNING, QStringLiteral("下线请求失败");
		}

		if (timer->isActive()) {
			timer->stop();
			Logger(ui.text_log, LEVEL_INFO, QStringLiteral("终止心跳服务"));
		}

		/* 恢复表单 */
		ui.button_toggle->setText(QStringLiteral("连接"));
		ui.line_code->setDisabled(false);
		ui.line_sno->setDisabled(false);
		ui.button_detect->setDisabled(false);
		ui.combo_service->setDisabled(false);

		ro->deleteLater(); /* 释放内存 */
	});
}

/* 判断网络是否连接 */
bool H3rHelper::imcConnected(int type) {
	QNetworkConfigurationManager ncm;
	auto nc = ncm.allConfigurations();

	QString ssid = (type == TYPE_LIB_S || type == TYPE_LIB) ? "NWPU-LIB" : "NWPU-WLAN";
	bool connected = false;
	for (auto &x : nc) {
		if (x.name() == ssid && x.state() == QNetworkConfiguration::Active) {
			connected = true;
			break;
		}
	}
	if (!connected) {
		Logger(ui.text_log, LEVEL_ERROR, QStringLiteral("未接入目标网络！"));
	}
	else {
		Logger(ui.text_log, LEVEL_INFO, QStringLiteral("热点连接正常"));
	}
	return connected;
}

/* 获取深澜用户状态信息 */
void H3rHelper::sRunGetInfo(int type) {
	/* 读取用户信息 */
	QSettings settings(
		"HKEY_CURRENT_USER\\Software\\H3rHelper",
		QSettings::NativeFormat
	);
	QString sno = settings.value("username", "").toString();
	QString code = settings.value("password", "").toString();

	/* 构造认证请求 */
	QUrl serviceUrl = QUrl(Service[type] + "auth_action.php");
	QUrlQuery postData;
	postData.addQueryItem("action", "get_online_info");
	postData.addQueryItem("ac_id", "1");
	postData.addQueryItem("username", sno);
	postData.addQueryItem("password", code);
	postData.addQueryItem("ajax", "1");

	QNetworkRequest request(serviceUrl);
	request.setHeader(
		QNetworkRequest::ContentTypeHeader,
		"application/x-www-form-urlencoded"
	);

	reply = networkManager->post(request, postData.toString(QUrl::FullyEncoded).toUtf8());
	last = "reply";

	connect(reply, &QNetworkReply::finished, [&] {
		if (reply == nullptr) { return; } // 操作被清空
		if (reply->error() == QNetworkReply::NoError) {
			QByteArray res = reply->readAll();
			QString s = QString::fromUtf8(res);
			QRegExp rx("E(\\d+): (.+)\\.\\((.+)\\)");
			if (s.contains("not_online", Qt::CaseInsensitive)) {
				Logger(ui.text_log, LEVEL_WARNING, QStringLiteral("状态：当前用户不在线"));
			}
			else {
				Logger(ui.text_log, LEVEL_ERROR, QStringLiteral("状态：用户在线"));
			}

			/* 恢复表单 */
			ui.button_toggle->setText(QStringLiteral("认证"));
			ui.line_code->setDisabled(false);
			ui.line_sno->setDisabled(false);
			ui.button_detect->setDisabled(false);
			ui.combo_service->setDisabled(false);
		}
		reply->deleteLater(); /* 释放内存 */
	});
}

/* sRun Portal 认证方法 */
void H3rHelper::sRunLogin(int type) {
	/* 读取用户信息 */
	QSettings settings(
		"HKEY_CURRENT_USER\\Software\\H3rHelper",
		QSettings::NativeFormat
	);
	QString sno = settings.value("username", "").toString();
	QString code = settings.value("password", "").toString();
	
	/* 构造认证请求 */
	QUrl serviceUrl = QUrl(Service[type] + "auth_action.php");
	QUrlQuery postData;
	postData.addQueryItem("action", "login");
	postData.addQueryItem("ac_id", "1");
	postData.addQueryItem("username", sno);
	postData.addQueryItem("password", code);
	postData.addQueryItem("ajax", "1");

	QNetworkRequest request(serviceUrl);
	request.setHeader(
		QNetworkRequest::ContentTypeHeader,
		"application/x-www-form-urlencoded"
	);

	reply = networkManager->post(request, postData.toString(QUrl::FullyEncoded).toUtf8());
	last = "reply";

	connect(reply, &QNetworkReply::finished, [&] {
		if (reply == nullptr) { return; } // 操作被清空
		if (reply->error() == QNetworkReply::NoError) {
			QByteArray res = reply->readAll();
			QString s = QString::fromUtf8(res);
			QRegExp rx("E(\\d+): (.+)\\.\\((.+)\\)");
			if (s.contains("Portal not response", Qt::CaseInsensitive)) {
				Logger(ui.text_log, LEVEL_ERROR, QStringLiteral("失败：服务器无响应"));
			}
			else if (s.contains("Nas type not found", Qt::CaseInsensitive)) {
				Logger(ui.text_log, LEVEL_ERROR, QStringLiteral("失败：找不到访问点"));
			}
			else if (s.contains("INFO failed, BAS respond timeout", Qt::CaseInsensitive)) {
				Logger(ui.text_log, LEVEL_ERROR, QStringLiteral("认证失败：响应超时"));
			}
			else if (s.contains("INFO Error", Qt::CaseInsensitive)) {
				Logger(ui.text_log, LEVEL_ERROR, QStringLiteral("服务器认证错误"));
			}
			else if (rx.indexIn(s, 0) != -1) {
				Logger(ui.text_log, LEVEL_ERROR, QStringLiteral("认证未通过"));
				Logger(ui.text_log, LEVEL_WARNING, "E" + rx.cap(1) + ": " + rx.cap(2) + "(" + rx.cap(3) + ")");
			}
			else if (s.contains("Authentication success,Welcome!", Qt::CaseInsensitive) || s.contains(QStringLiteral("网络已连接"), Qt::CaseInsensitive)) {
				Logger(ui.text_log, LEVEL_WARNING, QStringLiteral("认证成功"));
				Logger(ui.text_log, LEVEL_INFO, QStringLiteral("深澜支持 MAC 绑定功能，无需心跳"));
			}
			else {
				Logger(ui.text_log, LEVEL_ERROR, QStringLiteral("服务器响应异常，未认证"));
			}

			/* 恢复表单 */
			ui.button_toggle->setText(QStringLiteral("认证"));
			ui.line_code->setDisabled(false);
			ui.line_sno->setDisabled(false);
			ui.button_detect->setDisabled(false);
			ui.combo_service->setDisabled(false);
		}
		reply->deleteLater(); /* 释放内存 */
	});
}

/* SRun Portal 下线方法 */
void H3rHelper::sRunLogout(int type) {
	/* 读取用户信息 */
	QSettings settings(
		"HKEY_CURRENT_USER\\Software\\H3rHelper",
		QSettings::NativeFormat
	);
	QString sno = settings.value("username", "").toString();
	QString code = settings.value("password", "").toString();

	/* 构造认证请求 */
	QUrl serviceUrl = QUrl(Service[type] + "auth_action.php");
	QUrlQuery postData;
	postData.addQueryItem("action", "logout");
	postData.addQueryItem("ac_id", "1");
	postData.addQueryItem("username", sno);
	postData.addQueryItem("password", code);
	postData.addQueryItem("ajax", "1");

	QNetworkRequest request(serviceUrl);
	request.setHeader(
		QNetworkRequest::ContentTypeHeader,
		"application/x-www-form-urlencoded"
	);

	ro = networkManager->post(request, postData.toString(QUrl::FullyEncoded).toUtf8());
	last = "ro";

	connect(ro, &QNetworkReply::finished, [&] {
		if (ro == nullptr) { return; } // 操作被清空
		if (ro->error() == QNetworkReply::NoError) {
			QByteArray res = ro->readAll();
			QString s = QString::fromUtf8(res);
			if (s.contains(QStringLiteral("注销失败"), Qt::CaseInsensitive)) {
				Logger(ui.text_log, LEVEL_WARNING, QStringLiteral("注销失败，可能不在线或服务器无响应"));
			}
			else if (s.contains(QStringLiteral("您似乎未曾连接到网络"), Qt::CaseInsensitive)) {
				Logger(ui.text_log, LEVEL_WARNING, QStringLiteral("无需注销，似乎未曾连接到网络"));
			}
			else {
				Logger(ui.text_log, LEVEL_INFO, QStringLiteral("注销成功"));
			}

			/* 恢复表单 */
			ui.button_toggle->setText(QStringLiteral("认证"));
			ui.line_code->setDisabled(false);
			ui.line_sno->setDisabled(false);
			ui.button_detect->setDisabled(false);
			ui.combo_service->setDisabled(false);
		}
		ro->deleteLater(); /* 释放内存 */
	});
}

/* IMC Portal 认证方法 */
void H3rHelper::imcAuthorize(int type)
{
	/* 读取用户信息 */
	QSettings settings(
		"HKEY_CURRENT_USER\\Software\\H3rHelper",
		QSettings::NativeFormat
	);
	QString sno = settings.value("username", "").toString();
	QString code = settings.value("password", "").toString();

	code = code.toUtf8().toBase64();

	QUrl serviceUrl = QUrl(Service[type] + "pws?t=li");
	QUrlQuery postData;
	postData.addQueryItem("userName", sno);
	postData.addQueryItem("userPwd", code);

	QNetworkRequest request(serviceUrl);
	request.setHeader(
		QNetworkRequest::ContentTypeHeader,
		"application/x-www-form-urlencoded"
	);
	request.setRawHeader("Accept", "text/plain, */*; q=0.01");
	request.setRawHeader("Accept-Language", "zh-CN,zh;q=0.8");
	request.setRawHeader("Accept-Encoding", "gzip, deflate");

	reply = networkManager->post(request, postData.toString(QUrl::FullyEncoded).toUtf8());
	last = "reply";

	connect(reply, &QNetworkReply::finished, [&] {
		if (reply == nullptr) { return; } // 操作被清空
		if (reply->error() == QNetworkReply::NoError) {
			QByteArray res = reply->readAll();
			QString data = QByteArray::fromBase64(res);
			data = QUrl(data).fromPercentEncoding(data.toUtf8());
			QJsonDocument jsonResponse = QJsonDocument::fromJson(data.toUtf8());
			QJsonObject jsonObject = jsonResponse.object();
			if (!jsonObject.contains("errorNumber") ||
				jsonObject.take("errorNumber") == "1" &&
				jsonObject.contains("portalLink"))
			{
				/* 认证成功 */
				Logger(ui.text_log, LEVEL_INFO, QStringLiteral("认证成功"));
				if (!timer->isActive()) {
					timer->start();
					Logger(ui.text_log, LEVEL_INFO, QStringLiteral("心跳服务启动……"));

					/* 设置切换按钮 */
					ui.button_toggle->setText(QStringLiteral("下线"));
				}
			}
			else {
				/* 认证出错 */
				auto info = jsonObject.take("portServIncludeFailedReason").toString();
				if (info == "") {
					info = jsonObject.take("portServErrorCodeDesc").toString();

				}
				if (info == "") {
					info = QStringLiteral("（未知错误）");
				}
				Logger(ui.text_log, LEVEL_ERROR, QStringLiteral("认证失败！错误信息：") + info);
				if (timer->isActive()) {
					timer->stop();
					Logger(ui.text_log, LEVEL_INFO, QStringLiteral("终止心跳服务"));
				}

				/* 恢复表单 */
				ui.button_toggle->setText(QStringLiteral("连接"));
				ui.line_code->setDisabled(false);
				ui.line_sno->setDisabled(false);
				ui.button_detect->setDisabled(false);
				ui.combo_service->setDisabled(false);
			}
		}
		else {
			ui.text_log, LEVEL_ERROR, QStringLiteral("认证请求失败");
			if (timer->isActive()) {
				timer->stop();
				Logger(ui.text_log, LEVEL_INFO, QStringLiteral("终止心跳服务"));
			}

			/* 恢复表单 */
			ui.button_toggle->setText(QStringLiteral("连接"));
			ui.line_code->setDisabled(false);
			ui.line_sno->setDisabled(false);
			ui.button_detect->setDisabled(false);
			ui.combo_service->setDisabled(false);
		}

		reply->deleteLater(); /* 释放内存 */
	});
}

/* 响应托盘点击 */
void H3rHelper::on_activatedSysTrayIcon(QSystemTrayIcon::ActivationReason reason)
{
	switch (reason) {
		case QSystemTrayIcon::Trigger:
			// 单击托盘图标
			this->show();
			break;
	}
}
