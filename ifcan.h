/*!***************************************************
 * @file:	ifcan.h
 * @brief:	ifcan Header
 * @author:	Chen Dezhou
 * @date:	2020.02.18
 * @note:
 ****************************************************/

#ifndef _IF_CAN_H
#define _IF_CAN_H

#include <pthread.h>
#include <net/if.h>

#define IFCAN_DEBUG
#ifdef IFCAN_DEBUG
#define IFCAN_LOG(format, ...) fprintf(stdout, ">>>>>" format "<<<<", ##__VA_ARGS__)
#else
#define IFCAN_LOG(format, ...)
#endif


//使用CAN0
#define CAN0	0
//使用CAN1
#define CAN1 	1

//长包超时时间（秒）
#define IFCAN_LONG_PACKAGE_TIMEOUT	5
//长包缓存节点数
#define IFCAN_LONG_PACKAGE_MAX_CNT		512
//私钥
#define IFCAN_PRIVATE_KEY		0x5A
//业务层数据起始符
#define IFCAN_APP_START_CHAR	0xFF
//业务层数据结束符
#define IFCAN_APP_END_CHAR		0xFF
//业务层最大包长
#define IFCAN_MAX_DATA_LENGTH	896

//允许注册的最大线程数
#define IFCAN_MAX_REG_THREADS	30
//允许一个线程注册的最大消息数
#define IFCAN_MAX_REG_MSG_PER_THREAD	128


#define IFCAN_TYPE_DATA		0x00
#define IFCAN_TYPE_CMD		0x01
#define IFCAN_TYPE_ACK		0x02
#define IFCAN_TYPE_FIRMWARE	0x03


typedef unsigned char 	u8;
typedef unsigned short 	u16;
typedef unsigned int 	u32;
typedef unsigned long 	u64;
typedef int 			s32;


typedef struct _IfcanIdInfo
{
    u8	frameType;		//帧类型
    u8	reserved;		//保留位
    u8	splitFlag;		//分片帧标志
    u8	encryptFlag;	//加密标志
    u8	validateFlag;	//认证标志
    u8	sourceId;	//源节点地址
    u8	destId;		//目的地址ID
    u8	publicKey;		//公钥
} IfcanIdInfo;

typedef struct _IfcanLongPackageNode
{
    u8 	sourceId;		//源地址
    u16 currentPos;		//当前第一个可以写入的位置
    u8 	dataBuf[IFCAN_MAX_DATA_LENGTH];	//数据缓存区
    u16 dataLength;		//数据长度
    u8 	inUse;			//正在被占用
    u64 timeStamp;		//时间戳
} IfcanLongPackageNode;


typedef struct _IfcanDataPackage
{
    u8	packageType;//包类型
    u8	sourceId;	//消息源
    u8	*dataBuf;	//数据缓存区
    u32	dataLength;	//数据长度
} IfcanDataPackage;


typedef struct _IfcanConfiguration
{
	u8	encryptEnable;	//加密使能
	u8	validateEnable;	//认证使能
	u8	sourceId;		//自身sourceId
}IfcanConfiguration;


typedef struct _IfcanMsgId
{
	u8 	packageType;	//包类型
	u16 funCode;		//功能码
}IfcanMsgId;


typedef struct _IfcanMsgRegNode
{
	u32 msgId[IFCAN_MAX_REG_MSG_PER_THREAD];	//包类型|功能码
	u16 msgIdCnt;						//该线程已注册的消息数量
	u8 	pFlag;							//等待消息标志
	struct queue *msgQueueForThread;	//消息队列
	pthread_t tid;						//线程id
}IfcanMsgRegNode;


typedef struct _IfcanAppMsg
{
	u8 	dataBuf[IFCAN_MAX_DATA_LENGTH];	//数据（包含起始符、功能码、结束符）
	u16 dataLength;	//数据区长度
	u8 	sourceId;	//消息源Id
	u8 	packageType;//消息包类型
}IfcanAppMsg;


typedef struct _IfcanCase
{
	//长包缓存区
	IfcanLongPackageNode	ifcanLongPackageNode[IFCAN_LONG_PACKAGE_MAX_CNT];
	//上次使用的长包缓存节点
	u16 lastLongPackageNodePos;
	//ifcan 配置结构体
	IfcanConfiguration ifcanConfigurationGolbal;
	//ifcan 发送队列
	struct queue *ifcanSendQueue;	
	//消息兴趣表
	IfcanMsgRegNode ifcanMsgRegTable[IFCAN_MAX_REG_THREADS];
	//消息兴趣表锁
	pthread_mutex_t msgRegTableMutex;
	
	//被初始化标志
	u8 initializedFlag;
	
	//句柄
	s32 can_s;	
	struct ifreq ifr;
}IfcanCase;

static u32 ifcanIdParse(u32 canId, IfcanIdInfo *pInfo);
static u32 ifcanDecode(u8 publicKey, u8 privateKey, const u8 *primaryData, u8 *resData);
static u32 ifcanValidate(void);
static u64 ifcanGetTimestampInSeconds();
static u32 ifcanSplitPackageProcess(u8 whichCan,u8 packageType, u8 sourceId, u8 *pData);
static u32 ifcanClearLongPackageNode(u8 whichCan,u16 pos);
static u32 ifcanProcess(u8 whichCan,u32 canId, u8 *pData);
static u32 ifcanPushData(u8 whichCan,u8 packageType,u8 sourceId,u8 *pData,u16 dataLength);
static void *threadIfcanSend(void *arg);
static u32 ifcanLowLayerSend(u8 whichCan,u8 destId,u8 packageType,u8 *pData,u16 length);
static u32 ifcanHardwareTransmit(u8 whichCan,u8 destId,u8 packageType,u8 *pData,u16 length);

u32 ifcanSend(u8 whichCan,u8 destId,u8 packageType,u8 *pData,u16 length);
u32 ifcanMsgReg(u8 whichCan,u8 packageType,u16 *funCodeList,u16 funCodeCnt);
u32 ifcanMsgUnreg(u8 whichCan,u8 regCode,u8 packageType,u16 *funCodeList,u16 funCodeCnt);



#endif
