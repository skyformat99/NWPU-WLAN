#pragma once
#include <QtNetwork>
#include <QUrl>

/* 服务类型 */
#define	TYPE_AUTO	0
#define	TYPE_LIB_S	1
#define	TYPE_WLAN_S	2
#define	TYPE_LIB	3
#define	TYPE_137	4
#define	TYPE_138	5

/* 服务地址 */
QString Service[6] = {
	"",
	"http://222.24.192.66/include/",
	"http://222.24.192.66/include/",
	"http://202.117.80.137:8080/portal/",
	"http://202.117.80.137:8080/portal/",
	"http://202.117.80.138:8080/portal/"
};
