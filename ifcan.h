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


//ʹ��CAN0
#define CAN0	0
//ʹ��CAN1
#define CAN1 	1

//������ʱʱ�䣨�룩
#define IFCAN_LONG_PACKAGE_TIMEOUT	5
//��������ڵ���
#define IFCAN_LONG_PACKAGE_MAX_CNT		512
//˽Կ
#define IFCAN_PRIVATE_KEY		0x5A
//ҵ���������ʼ��
#define IFCAN_APP_START_CHAR	0xFF
//ҵ������ݽ�����
#define IFCAN_APP_END_CHAR		0xFF
//ҵ���������
#define IFCAN_MAX_DATA_LENGTH	896

//����ע�������߳���
#define IFCAN_MAX_REG_THREADS	30
//����һ���߳�ע��������Ϣ��
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
    u8	frameType;		//֡����
    u8	reserved;		//����λ
    u8	splitFlag;		//��Ƭ֡��־
    u8	encryptFlag;	//���ܱ�־
    u8	validateFlag;	//��֤��־
    u8	sourceId;	//Դ�ڵ��ַ
    u8	destId;		//Ŀ�ĵ�ַID
    u8	publicKey;		//��Կ
} IfcanIdInfo;

typedef struct _IfcanLongPackageNode
{
    u8 	sourceId;		//Դ��ַ
    u16 currentPos;		//��ǰ��һ������д���λ��
    u8 	dataBuf[IFCAN_MAX_DATA_LENGTH];	//���ݻ�����
    u16 dataLength;		//���ݳ���
    u8 	inUse;			//���ڱ�ռ��
    u64 timeStamp;		//ʱ���
} IfcanLongPackageNode;


typedef struct _IfcanDataPackage
{
    u8	packageType;//������
    u8	sourceId;	//��ϢԴ
    u8	*dataBuf;	//���ݻ�����
    u32	dataLength;	//���ݳ���
} IfcanDataPackage;


typedef struct _IfcanConfiguration
{
	u8	encryptEnable;	//����ʹ��
	u8	validateEnable;	//��֤ʹ��
	u8	sourceId;		//����sourceId
}IfcanConfiguration;


typedef struct _IfcanMsgId
{
	u8 	packageType;	//������
	u16 funCode;		//������
}IfcanMsgId;


typedef struct _IfcanMsgRegNode
{
	u32 msgId[IFCAN_MAX_REG_MSG_PER_THREAD];	//������|������
	u16 msgIdCnt;						//���߳���ע�����Ϣ����
	u8 	pFlag;							//�ȴ���Ϣ��־
	struct queue *msgQueueForThread;	//��Ϣ����
	pthread_t tid;						//�߳�id
}IfcanMsgRegNode;


typedef struct _IfcanAppMsg
{
	u8 	dataBuf[IFCAN_MAX_DATA_LENGTH];	//���ݣ�������ʼ���������롢��������
	u16 dataLength;	//����������
	u8 	sourceId;	//��ϢԴId
	u8 	packageType;//��Ϣ������
}IfcanAppMsg;


typedef struct _IfcanCase
{
	//����������
	IfcanLongPackageNode	ifcanLongPackageNode[IFCAN_LONG_PACKAGE_MAX_CNT];
	//�ϴ�ʹ�õĳ�������ڵ�
	u16 lastLongPackageNodePos;
	//ifcan ���ýṹ��
	IfcanConfiguration ifcanConfigurationGolbal;
	//ifcan ���Ͷ���
	struct queue *ifcanSendQueue;	
	//��Ϣ��Ȥ��
	IfcanMsgRegNode ifcanMsgRegTable[IFCAN_MAX_REG_THREADS];
	//��Ϣ��Ȥ����
	pthread_mutex_t msgRegTableMutex;
	
	//����ʼ����־
	u8 initializedFlag;
	
	//���
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
