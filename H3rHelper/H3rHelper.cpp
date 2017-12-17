#include "stdafx.h"
#include "H3rHelper.h"
#include "Logger.h"
#include "IMCPortal.h"

int status = 0;
QTimer *timer; // ������ʱ��
QTimer *timeout; // ̽�ⳬʱ����Ĳ����ã�
QNetworkAccessManager *networkManager; // ���������
QSystemTrayIcon * mSysTrayIcon; // ����ͼ��
/* ������Ӧ*/
QNetworkReply *r; // ���
QNetworkReply *ro; // ����
QNetworkReply *reply; // ��֤
QString last = ""; // ���ִ��

H3rHelper::H3rHelper(QWidget *parent)
	: QMainWindow(parent)
{
	ui.setupUi(this);
	/* ��ʼ������ */
	setFixedSize(
		this->geometry().width(),
		this->geometry().height()
	);
	setWindowTitle(QStringLiteral("�ϴ�����С����"));

	/* ����ѧУ��� */
	QImage * logo = new QImage(":/H3rHelper/Resources/logo.bmp");
	LogoScene *scene = new LogoScene;
	scene->addPixmap(QPixmap::fromImage(*logo));
	ui.logo->setScene(scene);
	ui.logo->setCursor(QCursor(Qt::PointingHandCursor));
	ui.logo->setStyleSheet("QGraphicsView { border-style: none; }");

	/* ���뱣�����Ϣ */
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

	/* ��֤����Ķ�ʱ��ѡ���л� */
	connect(ui.combo_service, static_cast<void (QComboBox::*)(const QString &)>(&QComboBox::currentIndexChanged), [this]() {
		int current = ui.combo_service->currentIndex();
		if (current >= TYPE_LIB) {
			ui.widget_action->setDisabled(true);
			ui.button_toggle->setText(QStringLiteral("����"));
			ui.button_info->setDisabled(true);
		}
		else {
			ui.widget_action->setDisabled(false);
			ui.button_toggle->setText(QStringLiteral("��֤"));
			ui.button_info->setDisabled(false);
		}
	});

	/* ��հ�ť */
	connect(ui.button_clear, &QPushButton::clicked, [this]() {
		auto b = QMessageBox::question(
			NULL,
			QStringLiteral("�����־"),
			QStringLiteral("��ȷ����"),
			QMessageBox::Yes | QMessageBox::No, QMessageBox::Yes
		);
		if (b == QMessageBox::Yes) {
			ui.text_log->clear();
		}
	});

	/* ��ʼ������ͼ�� */
	QSystemTrayIcon * mSysTrayIcon = new QSystemTrayIcon(this);
	QIcon icon = QIcon(":/H3rHelper/Resources/icon.png");
	mSysTrayIcon->setIcon(icon);
	mSysTrayIcon->setToolTip(QStringLiteral("�ϴ�����С����"));
	connect(
		mSysTrayIcon,
		SIGNAL(activated(QSystemTrayIcon::ActivationReason)),
		this,
		SLOT(on_activatedSysTrayIcon(QSystemTrayIcon::ActivationReason))
	);
	mSysTrayIcon->show();
	/* ���ص����̰�ť */
	connect(ui.button_hide, &QPushButton::clicked, [=]() {
		this->hide();
	});

	/* ��������ť */
	connect(ui.button_self, &QPushButton::clicked, [this]() {
		QString self = "http://zizhu.nwpu.edu.cn";
		QDesktopServices::openUrl(QUrl(self));
	});

	/* ��ʼ���л���ť */
	ui.button_toggle->setStyleSheet("QPushButton { font-weight: bold; }");
	ui.button_toggle->setText(QStringLiteral("����"));

	/* �л���ť���� */
	connect(ui.button_toggle, &QPushButton::clicked, [this]() {
		/* ��ȡ������Ϣ */
		QString sno = ui.line_sno->text();
		QString code = ui.line_code->text();

		/* �洢������Ϣ */
		QSettings settings(
			"HKEY_CURRENT_USER\\Software\\H3rHelper",
			QSettings::NativeFormat
		);
		settings.setValue("username", sno);
		settings.setValue("password", code);

		/* �ж������Ƿ�Ϊ�� */
		if (sno == "" || code == "") {
			QMessageBox::critical(
				NULL,
				QStringLiteral("����"),
				QStringLiteral("ѧ�ź����벻��Ϊ�գ�")
			);
			Logger(ui.text_log, LEVEL_ERROR, QStringLiteral("ѧ�ź����벻��Ϊ�գ�"));
			return;
		}

		/* ��ȡĿ����� */
		int i = ui.combo_service->currentIndex();
		if (i || ui.button_toggle->text() == QStringLiteral("ȡ��")) {
			auto op = ui.button_toggle->text();
			if (op == QStringLiteral("����")) {
				if (imcConnected(i)) {
					/* ���ñ� */
					ui.button_toggle->setText(QStringLiteral("ȡ��"));
					ui.line_code->setDisabled(true);
					ui.line_sno->setDisabled(true);
					ui.button_detect->setDisabled(true);
					ui.combo_service->setDisabled(true);

					imcAuthorize(i);
				}
			}
			else if (op == QStringLiteral("����")) {
				/* ���ñ� */
				ui.button_toggle->setText(QStringLiteral("ȡ��"));
				ui.line_code->setDisabled(true);
				ui.line_sno->setDisabled(true);
				ui.button_detect->setDisabled(true);
				ui.combo_service->setDisabled(true);

				imcLogout(i);
			}
			else if (op == QStringLiteral("ȡ��")) {
				/* ȡ������ */
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

				/* �ָ��� */
				if (ui.combo_service->currentIndex() <= TYPE_WLAN_S) {
					ui.button_toggle->setText(QStringLiteral("��֤"));
				}
				else {
					ui.button_toggle->setText(QStringLiteral("����"));
				}
				ui.line_code->setDisabled(false);
				ui.line_sno->setDisabled(false);
				ui.button_detect->setDisabled(false);
				ui.combo_service->setDisabled(false);
				Logger(ui.text_log, LEVEL_WARNING, QStringLiteral("����ȡ��������ֹͣ"));
			}
			else { // ��֤
				if (imcConnected(i)) {
					/* ���ñ� */
					ui.button_toggle->setText(QStringLiteral("ȡ��"));
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
				QStringLiteral("����"),
				QStringLiteral("��ѡ����Զ����Ŀ�����")
			);
			Logger(ui.text_log, LEVEL_ERROR, QStringLiteral("��ѡ����Զ����Ŀ�����"));
		}
	});

	/* ��ʼ���û�״̬��ť */
	connect(ui.button_info, &QPushButton::clicked, [this]() {
		if (ui.combo_service->currentIndex() && ui.combo_service->currentIndex() <= TYPE_WLAN_S) {
			int i = ui.combo_service->currentIndex();

			if (imcConnected(i)) {
				/* ���ñ� */
				ui.button_toggle->setText(QStringLiteral("ȡ��"));
				ui.line_code->setDisabled(true);
				ui.line_sno->setDisabled(true);
				ui.button_detect->setDisabled(true);
				ui.combo_service->setDisabled(true);

				sRunGetInfo(i);
			}
		}
		else {
			QMessageBox message(QMessageBox::Information, QStringLiteral("��ʾ"), QStringLiteral("��֧��������֤\n��ѡ�������ķ��������"));
			message.exec();
		}
	});

	/* ��ʼ��ʶ��ť */
	connect(ui.button_detect, &QPushButton::clicked, [this]() {
		/* ���ñ� */
		ui.combo_service->setDisabled(true);
		ui.button_detect->setDisabled(true);
		ui.button_toggle->setDisabled(true);

		/* ��ʾ�û�������ϵͳ��ѡ�� */
		QMessageBox messageBox(QMessageBox::Question,
			QStringLiteral("��֤ϵͳ"),
			QStringLiteral("����ѡ��ǰʹ�õ���֤ϵͳ\n��ʾ��������Ϊ�ϰ����"),
			QMessageBox::Yes | QMessageBox::No,
			this);
		messageBox.setButtonText(QMessageBox::Yes, QStringLiteral("����"));
		messageBox.setButtonText(QMessageBox::No, QStringLiteral("����"));
		auto b = messageBox.exec();
		if (b == QMessageBox::No) {
			sRunDetect();
		}
		else {
			imcDetect();
		}
	});

	/* ���ڶԻ��� */
	connect(ui.button_about, &QPushButton::clicked, [this]() {
		QMessageBox message(
			QMessageBox::NoIcon,
			QStringLiteral("���ڳ���"),
			QStringLiteral(
				"�ϴ�����С���� 1.0��<br /><br />"
				"2017 ��Ȩ���У����治��<br /><br />"
				"���������ѧϰ����֮�ã��Ͻ������κηǷ�����ҵĿ�ģ�Υ��һ�к�����ге���"
			)
		);
		message.setIconPixmap(QPixmap(":/H3rHelper/Resources/icon.png"));
		message.exec();
	});

	/* ��ʼ����������� */
	networkManager = new QNetworkAccessManager();
	/* ���ö�ʱ�� */
	timeout = new QTimer();
	timeout->setInterval(8000);
	timeout->setSingleShot(true);
	connect(timeout, &QTimer::timeout, [this]() {
		if (r->isRunning()) {
			r->abort();
		}
		r->deleteLater();

		/* �ָ��� */
		ui.combo_service->setDisabled(false);
		ui.button_detect->setDisabled(false);
		ui.button_toggle->setDisabled(false);

		/* �϶� 137 ������ */
		Logger(ui.text_log, LEVEL_WARNING, QStringLiteral("137���ɷ��ʣ��Զ�ѡΪ138"));
		Logger(ui.text_log, LEVEL_INFO, QStringLiteral("������Լ�����ȷ������׼ȷ��"));
		ui.combo_service->setCurrentIndex(TYPE_138);
	});
	timer = new QTimer();
	timer->setInterval(30000); // ��������Ϊ30��
	connect(timer, &QTimer::timeout, [this]() {
		imcAuthorize(ui.combo_service->currentIndex());
	});

	/* ��ʼ�������־ */
	Logger(ui.text_log, LEVEL_INFO, QStringLiteral("����������"));
}

/* sRun ʶ����� */
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
		Logger(ui.text_log, LEVEL_WARNING, QStringLiteral("δ��⵽����ѧУ����"));
	}

	/* �ָ��� */
	ui.combo_service->setDisabled(false);
	ui.button_detect->setDisabled(false);
	ui.button_toggle->setDisabled(false);
}

/* IMC ʶ����� */
void H3rHelper::imcDetect() {
	/* �ٶ������� 137 */
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
		/* �ָ��� */
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
			/* ���豸��������ʱ */
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

		r->deleteLater(); /* �ͷ��ڴ� */
	});
}

/* �������� */
void H3rHelper::imcLogout(int type) {
	QUrl serviceUrl = QUrl(Service[type] + "pws?t=lo");

	QNetworkRequest request(serviceUrl);
	request.setRawHeader("Accept", "text/plain, */*; q=0.01");
	request.setRawHeader("Accept-Language", "zh-CN,zh;q=0.8");
	request.setRawHeader("Accept-Encoding", "gzip, deflate");
	
	ro = networkManager->get(request);
	last = "ro";

	connect(ro, &QNetworkReply::finished, [=] {
		if (ro == nullptr) { return; } // ���������
		if (ro->error() == QNetworkReply::NoError) {
			QByteArray res = ro->readAll();
			QString data = QByteArray::fromBase64(res);
			data = QUrl(data).fromPercentEncoding(data.toUtf8());
			QJsonDocument jsonResponse = QJsonDocument::fromJson(data.toUtf8());
			QJsonObject jsonObject = jsonResponse.object();
			if (jsonObject.contains("portServErrorCodeDesc")) {
				/* �û��Ѿ����� */
				Logger(ui.text_log, LEVEL_WARNING, QStringLiteral("���棺") + jsonObject.take("portServErrorCodeDesc").toString());
			}
			else {
				Logger(ui.text_log, LEVEL_INFO, QStringLiteral("���߳ɹ���"));
			}
		}
		else {
			ui.text_log, LEVEL_WARNING, QStringLiteral("��������ʧ��");
		}

		if (timer->isActive()) {
			timer->stop();
			Logger(ui.text_log, LEVEL_INFO, QStringLiteral("��ֹ��������"));
		}

		/* �ָ��� */
		ui.button_toggle->setText(QStringLiteral("����"));
		ui.line_code->setDisabled(false);
		ui.line_sno->setDisabled(false);
		ui.button_detect->setDisabled(false);
		ui.combo_service->setDisabled(false);

		ro->deleteLater(); /* �ͷ��ڴ� */
	});
}

/* �ж������Ƿ����� */
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
		Logger(ui.text_log, LEVEL_ERROR, QStringLiteral("δ����Ŀ�����磡"));
	}
	else {
		Logger(ui.text_log, LEVEL_INFO, QStringLiteral("�ȵ���������"));
	}
	return connected;
}

/* ��ȡ�����û�״̬��Ϣ */
void H3rHelper::sRunGetInfo(int type) {
	/* ��ȡ�û���Ϣ */
	QSettings settings(
		"HKEY_CURRENT_USER\\Software\\H3rHelper",
		QSettings::NativeFormat
	);
	QString sno = settings.value("username", "").toString();
	QString code = settings.value("password", "").toString();

	/* ������֤���� */
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
		if (reply == nullptr) { return; } // ���������
		if (reply->error() == QNetworkReply::NoError) {
			QByteArray res = reply->readAll();
			QString s = QString::fromUtf8(res);
			QRegExp rx("E(\\d+): (.+)\\.\\((.+)\\)");
			if (s.contains("not_online", Qt::CaseInsensitive)) {
				Logger(ui.text_log, LEVEL_WARNING, QStringLiteral("״̬����ǰ�û�������"));
			}
			else {
				Logger(ui.text_log, LEVEL_ERROR, QStringLiteral("״̬���û�����"));
			}

			/* �ָ��� */
			ui.button_toggle->setText(QStringLiteral("��֤"));
			ui.line_code->setDisabled(false);
			ui.line_sno->setDisabled(false);
			ui.button_detect->setDisabled(false);
			ui.combo_service->setDisabled(false);
		}
		reply->deleteLater(); /* �ͷ��ڴ� */
	});
}

/* sRun Portal ��֤���� */
void H3rHelper::sRunLogin(int type) {
	/* ��ȡ�û���Ϣ */
	QSettings settings(
		"HKEY_CURRENT_USER\\Software\\H3rHelper",
		QSettings::NativeFormat
	);
	QString sno = settings.value("username", "").toString();
	QString code = settings.value("password", "").toString();
	
	/* ������֤���� */
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
		if (reply == nullptr) { return; } // ���������
		if (reply->error() == QNetworkReply::NoError) {
			QByteArray res = reply->readAll();
			QString s = QString::fromUtf8(res);
			QRegExp rx("E(\\d+): (.+)\\.\\((.+)\\)");
			if (s.contains("Portal not response", Qt::CaseInsensitive)) {
				Logger(ui.text_log, LEVEL_ERROR, QStringLiteral("ʧ�ܣ�����������Ӧ"));
			}
			else if (s.contains("Nas type not found", Qt::CaseInsensitive)) {
				Logger(ui.text_log, LEVEL_ERROR, QStringLiteral("ʧ�ܣ��Ҳ������ʵ�"));
			}
			else if (s.contains("INFO failed, BAS respond timeout", Qt::CaseInsensitive)) {
				Logger(ui.text_log, LEVEL_ERROR, QStringLiteral("��֤ʧ�ܣ���Ӧ��ʱ"));
			}
			else if (s.contains("INFO Error", Qt::CaseInsensitive)) {
				Logger(ui.text_log, LEVEL_ERROR, QStringLiteral("��������֤����"));
			}
			else if (rx.indexIn(s, 0) != -1) {
				Logger(ui.text_log, LEVEL_ERROR, QStringLiteral("��֤δͨ��"));
				Logger(ui.text_log, LEVEL_WARNING, "E" + rx.cap(1) + ": " + rx.cap(2) + "(" + rx.cap(3) + ")");
			}
			else if (s.contains("Authentication success,Welcome!", Qt::CaseInsensitive) || s.contains(QStringLiteral("����������"), Qt::CaseInsensitive)) {
				Logger(ui.text_log, LEVEL_WARNING, QStringLiteral("��֤�ɹ�"));
				Logger(ui.text_log, LEVEL_INFO, QStringLiteral("����֧�� MAC �󶨹��ܣ���������"));
			}
			else {
				Logger(ui.text_log, LEVEL_ERROR, QStringLiteral("��������Ӧ�쳣��δ��֤"));
			}

			/* �ָ��� */
			ui.button_toggle->setText(QStringLiteral("��֤"));
			ui.line_code->setDisabled(false);
			ui.line_sno->setDisabled(false);
			ui.button_detect->setDisabled(false);
			ui.combo_service->setDisabled(false);
		}
		reply->deleteLater(); /* �ͷ��ڴ� */
	});
}

/* SRun Portal ���߷��� */
void H3rHelper::sRunLogout(int type) {
	/* ��ȡ�û���Ϣ */
	QSettings settings(
		"HKEY_CURRENT_USER\\Software\\H3rHelper",
		QSettings::NativeFormat
	);
	QString sno = settings.value("username", "").toString();
	QString code = settings.value("password", "").toString();

	/* ������֤���� */
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
		if (ro == nullptr) { return; } // ���������
		if (ro->error() == QNetworkReply::NoError) {
			QByteArray res = ro->readAll();
			QString s = QString::fromUtf8(res);
			if (s.contains(QStringLiteral("ע��ʧ��"), Qt::CaseInsensitive)) {
				Logger(ui.text_log, LEVEL_WARNING, QStringLiteral("ע��ʧ�ܣ����ܲ����߻����������Ӧ"));
			}
			else if (s.contains(QStringLiteral("���ƺ�δ�����ӵ�����"), Qt::CaseInsensitive)) {
				Logger(ui.text_log, LEVEL_WARNING, QStringLiteral("����ע�����ƺ�δ�����ӵ�����"));
			}
			else {
				Logger(ui.text_log, LEVEL_INFO, QStringLiteral("ע���ɹ�"));
			}

			/* �ָ��� */
			ui.button_toggle->setText(QStringLiteral("��֤"));
			ui.line_code->setDisabled(false);
			ui.line_sno->setDisabled(false);
			ui.button_detect->setDisabled(false);
			ui.combo_service->setDisabled(false);
		}
		ro->deleteLater(); /* �ͷ��ڴ� */
	});
}

/* IMC Portal ��֤���� */
void H3rHelper::imcAuthorize(int type)
{
	/* ��ȡ�û���Ϣ */
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
		if (reply == nullptr) { return; } // ���������
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
				/* ��֤�ɹ� */
				Logger(ui.text_log, LEVEL_INFO, QStringLiteral("��֤�ɹ�"));
				if (!timer->isActive()) {
					timer->start();
					Logger(ui.text_log, LEVEL_INFO, QStringLiteral("����������������"));

					/* �����л���ť */
					ui.button_toggle->setText(QStringLiteral("����"));
				}
			}
			else {
				/* ��֤���� */
				auto info = jsonObject.take("portServIncludeFailedReason").toString();
				if (info == "") {
					info = jsonObject.take("portServErrorCodeDesc").toString();

				}
				if (info == "") {
					info = QStringLiteral("��δ֪����");
				}
				Logger(ui.text_log, LEVEL_ERROR, QStringLiteral("��֤ʧ�ܣ�������Ϣ��") + info);
				if (timer->isActive()) {
					timer->stop();
					Logger(ui.text_log, LEVEL_INFO, QStringLiteral("��ֹ��������"));
				}

				/* �ָ��� */
				ui.button_toggle->setText(QStringLiteral("����"));
				ui.line_code->setDisabled(false);
				ui.line_sno->setDisabled(false);
				ui.button_detect->setDisabled(false);
				ui.combo_service->setDisabled(false);
			}
		}
		else {
			ui.text_log, LEVEL_ERROR, QStringLiteral("��֤����ʧ��");
			if (timer->isActive()) {
				timer->stop();
				Logger(ui.text_log, LEVEL_INFO, QStringLiteral("��ֹ��������"));
			}

			/* �ָ��� */
			ui.button_toggle->setText(QStringLiteral("����"));
			ui.line_code->setDisabled(false);
			ui.line_sno->setDisabled(false);
			ui.button_detect->setDisabled(false);
			ui.combo_service->setDisabled(false);
		}

		reply->deleteLater(); /* �ͷ��ڴ� */
	});
}

/* ��Ӧ���̵�� */
void H3rHelper::on_activatedSysTrayIcon(QSystemTrayIcon::ActivationReason reason)
{
	switch (reason) {
		case QSystemTrayIcon::Trigger:
			// ��������ͼ��
			this->show();
			break;
	}
}
