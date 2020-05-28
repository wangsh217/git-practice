/*!***************************************************
 * @file:	ifcan.c
 * @brief:	ifcan Source
 * @author:	Chen Dezhou
 * @date:	2020.02.28
 * @note:
 ****************************************************/
#include <stdio.h>
#include <sys/time.h>
#include <pthread.h>
#include <stdlib.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>


#include "ifcan.h"
#include "lib/libqueue/libqueue.h"


IfcanCase ifcanCase[2];

/*!***************************************************
 * 从can id中解析出其中包含的can帧信息
 * @param:   	canId-从can底层接收到的can29位Id
				pInfo-用于存放解析出的帧信息
 * @return:  	0-成功
				其他-失败
 * @note: 		在ifcanProcess函数中调用
 ****************************************************/
static u32 ifcanIdParse(u32 canId, IfcanIdInfo *pInfo)
{
    if(pInfo == NULL)
    {
        IFCAN_LOG("ifcanIdParse:pInfo==null!\r\n");
        return -1;
    }

    pInfo->publicKey = (u8)(canId & (0x000000ff));
    pInfo->destId = (u8)((canId >> 8) & 0x0000007f);
    pInfo->sourceId = (u8)((canId >> 15) & 0x0000007f);
    pInfo->validateFlag = (u8)((canId >> 22) & 0x00000001);
    pInfo->encryptFlag = (u8)((canId >> 23) & 0x00000001);
    pInfo->splitFlag = (u8)((canId >> 24) & 0x00000001);
    pInfo->reserved = (u8)((canId >> 25) & 0x00000001);
    pInfo->frameType = (u8)((canId >> 26) & 0x00000007);

    return 0;
}

/*!***************************************************
 * 根据公钥、私钥对can 8字节数据进行解密
 * @param:   	publicKey-8位公钥
				privateKey-8位私钥
				primaryData-原数据区
				resData-用于存放解密后的数据
 * @return:  	0-成功
				其他-失败
 * @note: 		在ifcanProcess函数中调用,一次解密操作为8字节数据，不可增加/删减
 ****************************************************/
static u32 ifcanDecode(u8 publicKey, u8 privateKey, const u8 *primaryData, u8 *resData)
{
    u8 factor, i;

    if(resData == NULL)
    {
        IFCAN_LOG("ifcanDecode:resData==null!\r\n");
        return -1;
    }

    //加密因子
    factor = publicKey ^ privateKey;

    for(i = 0; i < 8; i++)
    {
        *(resData + i) = primaryData[i] ^ factor;
    }

    return 0;
}

/*!***************************************************
 * ifcan认证
 * @param:
 * @return:  	0-成功
				其他-失败
 * @note: 		在ifcanProcess函数中调用
 ****************************************************/
static u32 ifcanValidate(void)
{
    //待完善...
    return 0;
}

/*!***************************************************
 * 获取系统时间戳，单位为秒
 * @param:
 * @return:  	时间戳 秒
 * @note:
 ****************************************************/
static u64  ifcanGetTimestampInSeconds()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec;
}

/*!***************************************************
 * ifcan分片报处理
 * @param:   	sourceId-消息源Id
				pData-8字节数据区
 * @return:  	0-成功
				1-未能找到可用长包缓存节点
				2-断包，丢弃
 * @note: 		在ifcanProcess函数中调用,每次只处理8字节,不可增加删减
 ****************************************************/
static u32 ifcanSplitPackageProcess(u8 whichCan,u8 packageType, u8 sourceId, u8 *pData)
{
    u32 i;

    u8 nodeAvailable = 0;

    u32 existNodePos, currentPosInNode;

    u8 currentFrameCnt;

    u64 timeStamp;


    currentFrameCnt = pData[0] & 0x7F;

    //1.先判断是否是第1包
    //如果是第一包：1.清除已有缓存；2.申请新节点
    if(currentFrameCnt == 0x00)
    {
        //搜索可用节点之前先清除超时节点
        timeStamp = ifcanGetTimestampInSeconds();

        for(i = 0; i < IFCAN_LONG_PACKAGE_MAX_CNT; i++)
        {
            if((timeStamp - ifcanCase[whichCan].ifcanLongPackageNode[i].timeStamp) > IFCAN_LONG_PACKAGE_TIMEOUT)
            {
                ifcanClearLongPackageNode(whichCan,i);
            }
        }

        for(i = 0; i < IFCAN_LONG_PACKAGE_MAX_CNT; i++)
        {
            //同源且正在使用中
            if((sourceId == ifcanCase[whichCan].ifcanLongPackageNode[i].sourceId) && (1 == ifcanCase[whichCan].ifcanLongPackageNode[i].inUse))
            {
                ifcanClearLongPackageNode(whichCan,i);
                break;
            }
        }

		//从第0个节点开始搜索可用节点
		for(i=0;i<IFCAN_LONG_PACKAGE_MAX_CNT;i++)
		{
			if(0 == ifcanCase[whichCan].ifcanLongPackageNode[i].inUse)
			{
				ifcanCase[whichCan].lastLongPackageNodePos = i;
				nodeAvailable = 1;
				break;
			}
		}
    

        //未能找到可用节点
        if(0 == nodeAvailable)
        {
            IFCAN_LOG("ifcanSplitPackageProcess: No long package buffer node available!\r\n");
            return 1;
        }


		//设置当前节点的sourceId
		ifcanCase[whichCan].ifcanLongPackageNode[ifcanCase[whichCan].lastLongPackageNodePos].sourceId=sourceId;
        //占用搜索到的可用节点，并把数据复制到其缓存区
        ifcanCase[whichCan].ifcanLongPackageNode[ifcanCase[whichCan].lastLongPackageNodePos].inUse = 1;
        for(i = 0; i < 7; i++)
        {
            ifcanCase[whichCan].ifcanLongPackageNode[ifcanCase[whichCan].lastLongPackageNodePos].dataBuf[i] = pData[i + 1];
        }

        //更新可写入位置
        ifcanCase[whichCan].ifcanLongPackageNode[ifcanCase[whichCan].lastLongPackageNodePos].currentPos = 7;

        //更新节点时间戳
        ifcanCase[whichCan].ifcanLongPackageNode[ifcanCase[whichCan].lastLongPackageNodePos].timeStamp = ifcanGetTimestampInSeconds();

        return 0;

    }//if(currentFrameCnt==0x00)
    else	//如果不是第一包则在已有节点中查找同源节点
    {
        for(i = 0; i < IFCAN_LONG_PACKAGE_MAX_CNT; i++)
        {
            if(		(1 == ifcanCase[whichCan].ifcanLongPackageNode[i].inUse)					//正在使用中
                    &&	(sourceId == ifcanCase[whichCan].ifcanLongPackageNode[i].sourceId)		//同源
                    &&	((currentFrameCnt * 7) == ifcanCase[whichCan].ifcanLongPackageNode[i].currentPos)	//数据连续
              )
            {
                break;
            }
        }

        //未找到该sourceId的设备之前的消息缓存，则返回失败
        if(IFCAN_LONG_PACKAGE_MAX_CNT == i)
        {
            IFCAN_LOG("ifcanSplitPackageProcess:Illegal Long Package Frame Data\r\n");
            return 2;
        }

        existNodePos = i;
        currentPosInNode = ifcanCase[whichCan].ifcanLongPackageNode[i].currentPos;

        //复制数据
        for(i = 0; i < 7; i++)
        {
            ifcanCase[whichCan].ifcanLongPackageNode[existNodePos].dataBuf[currentPosInNode + i] = pData[i + 1];
        }

        //更新可写入位置
        ifcanCase[whichCan].ifcanLongPackageNode[existNodePos].currentPos += 7;


        //是否最后一帧?
        if((pData[0] >> 7) != 0x00)
        {
        	ifcanCase[whichCan].ifcanLongPackageNode[existNodePos].dataLength = ifcanCase[whichCan].ifcanLongPackageNode[existNodePos].currentPos;
            //通知应用层接收数据
       		ifcanPushData(
			whichCan,
			packageType,
			sourceId,
			ifcanCase[whichCan].ifcanLongPackageNode[existNodePos].dataBuf,
			ifcanCase[whichCan].ifcanLongPackageNode[existNodePos].dataLength);

			//清除节点的占用
			ifcanCase[whichCan].ifcanLongPackageNode[existNodePos].inUse=0;
			ifcanCase[whichCan].ifcanLongPackageNode[existNodePos].currentPos=0;
			ifcanCase[whichCan].ifcanLongPackageNode[existNodePos].dataLength=0;
        }

        return 0;

    }//if(pData[0]==0x00) else {...}
}

/*!***************************************************
 * ifcanLongPackageNode清除
 * @param:   	pos-需要清除的节点位置
 * @return:		0-成功
				1-位置超限
 * @note:
 ****************************************************/
static u32 ifcanClearLongPackageNode(u8 whichCan,u16 pos)
{

    u32 i;
    //1.判断位置是否合法
    if(pos >= IFCAN_LONG_PACKAGE_MAX_CNT)
    {
        IFCAN_LOG("ifcanClearLongPackageNode:pos=%d exceed the Max NUM %d\r\n", pos, IFCAN_LONG_PACKAGE_MAX_CNT);
        return 1;
    }

    //2.清除数据区
    for(i = 0; i < 896; i++)
    {
        ifcanCase[whichCan].ifcanLongPackageNode[pos].dataBuf[i] = 0x00;
    }
    //3.清除占用标志
    ifcanCase[whichCan].ifcanLongPackageNode[pos].inUse = 0;
    ifcanCase[whichCan].ifcanLongPackageNode[pos].currentPos = 0;
    ifcanCase[whichCan].ifcanLongPackageNode[pos].dataLength = 0;
}

/*!***************************************************
 * 对从CAN底层接收到的29位ID和8字节数据作处理
 * @param:   	canId-从can底层接收到的can29位Id
				-用于存放解析出的帧信息
 * @return:  	0-成功
				其他-失败
 * @note: 		在底层接收到can数据时调用本函数
 ****************************************************/
static u32 ifcanProcess(u8 whichCan,u32 canId, u8 *pData)
{
    //用于存放本帧can消息29位Id中包含的信息
    IfcanIdInfo ifcanIdInfo;
    //用于返回错误码
    u32 err, i;

    //存放解密后的数据
    u8 canFrameData[8];


    //1.解析出 帧类型、分片标志、加密标志、认证标志、源节点地址、公钥
    err = ifcanIdParse(canId, &ifcanIdInfo);
    if(err != 0)
    {
        IFCAN_LOG("ifcanIdParse returned error,err=%d\r\n", err);
        return err;
    }

    //2.解密
    if(1 == ifcanIdInfo.encryptFlag)
    {
        //解密之后的数据存放在 canFrameData
        err = ifcanDecode(ifcanIdInfo.publicKey, IFCAN_PRIVATE_KEY, pData, canFrameData);
        if(err != 0)
        {
            IFCAN_LOG("ifcanDecode returned error,err=%d\r\n", err);
            return err;
        }
    }
    else
    {
        for(i = 0; i < 8; i++)
        {
            canFrameData[i] = pData[i];
        }
    }

    //3.认证
    if(1 == ifcanIdInfo.validateFlag)
    {
        err = ifcanValidate();
        if(err != 0)
        {
            IFCAN_LOG("ifcanValidate returned error,err=%d\r\n", err);
            return err;
        }
    }

    //分片处理
    if(1 == ifcanIdInfo.splitFlag)
    {
        err = ifcanSplitPackageProcess(whichCan,ifcanIdInfo.frameType,ifcanIdInfo.sourceId, canFrameData);
        if(err != 0)
        {
            IFCAN_LOG("ifcanValidate returned error,err=%d\r\n", err);
            return err;
        }
    }
    else
    {
		//通知应用层收数据
        ifcanPushData(whichCan,ifcanIdInfo.frameType,ifcanIdInfo.sourceId,canFrameData,8);
    }
}






/*!***************************************************
 * 将can底层收到的数据推送到相应线程的接收队列
 * @param:   	whichCan-使用哪个CAN口，CAN0/CAN1
				packageType-包类型
				sourceId-消息源Id
				pData-数据缓冲区
				dataLength-有效数据长度
				
 * @return:  	0-成功
				1-没有兴趣线程正在等待该消息
				2-队列节点获取失败
 * @note: 		在底层接收到can数据时调用本函数
 ****************************************************/
static u32 ifcanPushData(u8 whichCan,u8 packageType,u8 sourceId,u8 *pData,u16 dataLength)
{
	struct item *ifcanAppMsgItem;	
	u16 funCode;
	u32 msgId;	
	IfcanAppMsg ifcanAppMsg;	
	u32 i,j,k;
	struct queue *q;
	
	q=NULL;
	
	for(i=0;i<dataLength;i++)
	{
		ifcanAppMsg.dataBuf[i]=pData[i];
	}
	ifcanAppMsg.dataLength=dataLength;
	ifcanAppMsg.sourceId=sourceId;
	ifcanAppMsg.packageType=packageType;	
	
	funCode=(pData[1]<<8)|pData[2];
	msgId=(packageType<<16)|funCode;

	//根据 packageType 和 pData[1] pData[2] 搜索匹配的 线程兴趣点
	if((packageType==IFCAN_TYPE_DATA)||(packageType==IFCAN_TYPE_ACK))
	{
		for(i=0;i<IFCAN_MAX_REG_THREADS;i++)
		{
			for(j=0;j<IFCAN_MAX_REG_MSG_PER_THREAD;j++)
			{
				//仅匹配 packageType， 不匹配funCode
				
				if((((ifcanCase[whichCan].ifcanMsgRegTable[i].msgId[j])>>16)&(0x0003))==packageType)
				{
					
					//接收队列正常、且pFlag=1
					if((ifcanCase[whichCan].ifcanMsgRegTable[i].msgQueueForThread!=NULL)&&(ifcanCase[whichCan].ifcanMsgRegTable[i].pFlag==1))
					{
						q=ifcanCase[whichCan].ifcanMsgRegTable[i].msgQueueForThread;
						break;
					}
				}//if((((ifcanCase[whichCan].ifcanMsgRegTable[i].msgId[j])>>16)&(0x0003))==packageType)
			}//for(j=0;j<;j++)
			
			if(q!=NULL)	break;
		}//for(i=0;i<IFCAN_MAX_REG_THREADS;i++)
	}//if((packageType==IFCAN_TYPE_DATA)||(packageType==IFCAN_TYPE_ACK))
	else if(packageType==IFCAN_TYPE_CMD)
	{

		for(i=0;i<IFCAN_MAX_REG_THREADS;i++)
		{
			for(j=0;j<IFCAN_MAX_REG_MSG_PER_THREAD;j++)
			{
				//匹配完整msgId
				if((ifcanCase[whichCan].ifcanMsgRegTable[i].msgId[j])==msgId)//删除了右移16
				{
          
					//接收队列正常、且pFlag=1
					if((ifcanCase[whichCan].ifcanMsgRegTable[i].msgQueueForThread!=NULL)&&(ifcanCase[whichCan].ifcanMsgRegTable[i].pFlag==1))
					{
						q=ifcanCase[whichCan].ifcanMsgRegTable[i].msgQueueForThread;
						break;
					}
					 else
          			{
            			IFCAN_LOG("msgQueueForThread or pFlag abnormal\r\n");
            		if(ifcanCase[whichCan].ifcanMsgRegTable[i].msgQueueForThread==NULL)
            		{
              			IFCAN_LOG("msgQueueForThread =NULL\r\n");
            		}
            		else if(ifcanCase[whichCan].ifcanMsgRegTable[i].pFlag!=1)
            		{
              			IFCAN_LOG("pFlag!=1\r\n");
            		}          
          }
				}//if((((ifcanCase[whichCan].ifcanMsgRegTable[i].msgId[j])>>16)&(0x0003))==packageType)
			}//for(j=0;j<;j++)
			
			if(q!=NULL)	break;
		}//for(i=0;i<IFCAN_MAX_REG_THREADS;i++)		
	}

	if(q==NULL)
	{
		IFCAN_LOG("ifcanPushData:No pending thread is interested int this Msg, MsgId=%x\r\n",msgId);
		return 1;
	}
	
	ifcanAppMsgItem=(struct item *)item_alloc(q,&ifcanAppMsg,sizeof(ifcanAppMsg),NULL);
	if(ifcanAppMsgItem==NULL)
	{
		IFCAN_LOG("ifcanPushData:ifcanAppMsgItem Memory required failed!\r\n",msgId);
		return 2;
	}
	//插入相应接收队列
	queue_push(q,ifcanAppMsgItem);
}

/*!***************************************************
 * CAN底层发送线程
 * @param:   	arg-线程创建时，传入的参数
 * @return:  	
 * @note: 		该函数不会返回
 ****************************************************/
static void *threadIfcanSend(void *arg)       
{
	struct item *itemToSend;
	
	u8 destId,packageType;

	u32 i;
	
	u8 whichCan=*(u8 *)arg;
	
	//whichCan-使用哪个CAN口，CAN0/CAN1
	if((whichCan!=CAN0)&&(whichCan!=CAN1))
	{
		IFCAN_LOG("threadIfcanSend: whichCan error!\r\n");
		return NULL;
	}
	

	while(1)
	{
		//从队列中取出一个待发送的数据节点
		
		itemToSend=queue_pop(ifcanCase[whichCan].ifcanSendQueue,0);
		if(itemToSend!=NULL)
		{
			//解析出待发送数据，调用发送函数
			
			destId=*((u8 *)(itemToSend->data.iov_base+itemToSend->data.iov_len-2));
			packageType=*((u8 *)itemToSend->data.iov_base+itemToSend->data.iov_len-1);

			ifcanLowLayerSend(whichCan,destId,packageType,itemToSend->data.iov_base,itemToSend->data.iov_len-2);
			
			//释放该节点内存
			item_free(ifcanCase[whichCan].ifcanSendQueue,itemToSend);
		}
	}
    
    return NULL;
}



/*!***************************************************
 * CAN底层接收线程
 * @param:   	arg-线程创建时，传入的参数
 * @return:  	
 * @note: 		该函数不会返回
 ****************************************************/
static void *threadIfcanReceive(void *arg)       
{
	struct item *itemToSend;
	u8 whichCan=*(u8 *)arg;
	
	
	int nbytes;
	struct can_frame frame;
	struct can_filter rfilter[1];
	struct sockaddr_can addr;
  
	if(whichCan==CAN0)
	{
		IFCAN_LOG("threadIfcanReceive: CAN0 Receive\r\n");
		strcpy(ifcanCase[whichCan].ifr.ifr_name, "can0" );
	}
	else if(whichCan==CAN1)
	{
		IFCAN_LOG("threadIfcanReceive: CAN1 Receive\r\n");
		strcpy(ifcanCase[whichCan].ifr.ifr_name, "can1" );
	}
	else
	{
		while(1)
		{
			IFCAN_LOG("threadIfcanReceive: whichCan parameter error\r\n");
			sleep(1);
		}
		
	}
  
    ifcanCase[whichCan].can_s=socket(PF_CAN, SOCK_RAW, CAN_RAW); //创建套接字
	
	
	if(ifcanCase[whichCan].can_s<0)
	{
		while(1)
		{
			IFCAN_LOG("threadIfcanReceive: socket returned error,can socket create failed!\r\n");
			sleep(1);
		}
	}
		


    ioctl(ifcanCase[whichCan].can_s, SIOCGIFINDEX, &ifcanCase[whichCan].ifr); //指定 can 设备
	addr.can_family = AF_CAN;
	
	addr.can_ifindex = ifcanCase[whichCan].ifr.ifr_ifindex;
	
	bind(ifcanCase[whichCan].can_s, (struct sockaddr *)&addr, sizeof(addr)); //将套接字与 can0 绑定
	
	rfilter[0].can_id = (ifcanCase[whichCan].ifcanConfigurationGolbal.sourceId)<<8;
	
	rfilter[0].can_mask = 0x00007F00;
  
	//设置过滤规则
	setsockopt(ifcanCase[whichCan].can_s, SOL_CAN_RAW, CAN_RAW_FILTER, &rfilter, sizeof(rfilter));
    int i; 
	while(1)
    {
		nbytes = read(ifcanCase[whichCan].can_s, &frame, sizeof(frame)); //接收报文
		if(nbytes > 0)
		{
		/*printf("++++++the  recevied data are: \r\n");
			for (i = 0; i < 8; i++)
				{
				printf("%x ",frame.data[i]);
				}
			printf("\r\n");
			*/
			ifcanProcess(whichCan,frame.can_id,frame.data);
		}
    }
	
    return NULL;
}


/*!***************************************************
 * CAN底层发送函数
 * @param:   	whichCan-使用哪个CAN口，CAN0/CAN1
				destId-目的Id
				packageType-包类型
				pData-数据缓存区首地址
				length-业务层需要发送的数据总长度
 * @return:  	
				0-成功
				1-whichCan参数错误
 * @note: 		该函数传入的数据为加密之前的明文数据
 ****************************************************/
static u32 ifcanLowLayerSend(u8 whichCan,u8 destId,u8 packageType,u8 *pData,u16 length)
{	
	//ifcan 分包缓存区
	static u8 splitBuf[IFCAN_MAX_DATA_LENGTH+(IFCAN_MAX_DATA_LENGTH/7)];
	
	u8 factor,timeStamp,totalFrameCount;
	u16 i,j,totalLength;
	
	
	//whichCan-使用哪个CAN口，CAN0/CAN1
	if((whichCan!=CAN0)&&(whichCan!=CAN1))
	{
		IFCAN_LOG("ifcanLowLayerSend: whichCan error!\r\n");
		return 1;
	}
	
	if(length>8)
	{
		//计算总帧数
		totalFrameCount=length/7;
		if(length%7!=0)
		{
			totalFrameCount+=1;
		}

		//1.分包,将待发送数据以7字节为单位分成段，并在各段之前，加上序号
		for(j=0;j<totalFrameCount;j++)
		{
			//把各帧序号填在序号的位置
			splitBuf[j*8]=j;
			
			for(i=7*j;i<7*j+7;i++)
			{
				splitBuf[i+j+1]=pData[i];
				
				//超过原始长度，但最后一包尚未满，需要补0
				if(i>=length)
				{
					splitBuf[i+j+1]=0x00;
				}
			}
		}
		//最后一帧，序号最高位置1，表示尾帧
		j--;
		splitBuf[j*8]|=0x80;
		
		//总长度
		totalLength=(j+1)*8;
		
		ifcanHardwareTransmit(whichCan,destId,packageType,splitBuf,totalLength);
	}
	else
	{
		//如果包长<=8,则
		ifcanHardwareTransmit(whichCan,destId,packageType,pData,length);
	}
	return 0;
}

/*!***************************************************
 * CAN底层发送函数
 * @param:   	whichCan-使用哪个CAN口，CAN0/CAN1
				destId-目的Id
				packageType-包类型
				pData-数据缓存区首地址
				length-CAN底层需要发送的数据总长度（包括分片相关字节）
				
 * @return:  	0-成功
				1-whichCan 参数错误
				2-相应的 can socket 尚未创建
				
 * @note: 		该函数传入的数据为加密之前的明文数据
 ****************************************************/
static u32 ifcanHardwareTransmit(u8 whichCan,u8 destId,u8 packageType,u8 *pData,u16 length)
{
	u8 sendBuf[8];
	u32 canId=0;	
	u8 i,j;
	u8 timeStamp=ifcanGetTimestampInSeconds()%8;
	u8 factor;
	
	struct can_frame frame_tx;
	
			
	//whichCan-使用哪个CAN口，CAN0/CAN1
	if((whichCan!=CAN0)&&(whichCan!=CAN1))
	{
		IFCAN_LOG("ifcanHardwareTransmit: whichCan error!\r\n");
		return 1;
	}
	
	//包类型
	canId|=packageType<<26;	
	
	//分片包标志
	if(length>8)
	{
		canId|=1<<24;
	}
	
	//加密标志
	if(ifcanCase[whichCan].ifcanConfigurationGolbal.encryptEnable)
	{
		canId|=1<<23;
	}
	
	//源地址
	canId|=ifcanCase[whichCan].ifcanConfigurationGolbal.sourceId<<15;
	//目的地址
	canId|=destId<<8;
	//公钥（时间戳-秒）
	canId|=timeStamp;
	
	//加密因子
	factor=timeStamp^IFCAN_PRIVATE_KEY;
		
	//循环发送数据
	i=0;
	do
	{
		for(j=0;j<8;j++)
		{
			sendBuf[j]=pData[i*8+j];
			
			//超出部分置0
			if(j>length-1)
				sendBuf[j]=0;
			//根据配置，启用加密
			if(ifcanCase[whichCan].ifcanConfigurationGolbal.encryptEnable)
				sendBuf[j]^=factor;
		}
		
		//调用系统提供的CAN发送函数
		
		
		frame_tx.can_id = CAN_EFF_FLAG|canId;

		frame_tx.can_dlc =8;
		
		
		for(j=0;j<8;j++)
		{
			frame_tx.data[j]=sendBuf[j];
		}

		if(ifcanCase[whichCan].can_s>0)
		{		
			write(ifcanCase[whichCan].can_s,&frame_tx,sizeof(frame_tx));
			usleep(1500);
				
		}
		else
		{	
			IFCAN_LOG("the coresponding can socket has not been created yet!\r\n");
			return 2;			
		}
		
		i++;
	}while(i<length/8);
	
	return 0;
}

/*!***************************************************
 * ifcan发送数据的API
 * @param:   	whichCan-使用哪个CAN口，CAN0/CAN1
				destId-需要发送的目的节点地址
				packageType-包类型 IFCAN_TYPE_DATA/IFCAN_TYPE_CMD/IFCAN_TYPE_ACK/IFCAN_TYPE_FIRMWARE
				pData-数据缓存区
				length-数据长度
 * @return:  	0-成功
				1-ifcan尚未初始化
				2-长度过长
				3-包类型错误
				4-发送数据节点内存申请失败
				5-插入队列失败
				6-whichCan参数错误
				
 * @note: 		该函数是应用程序通过ifcan发送数据的唯一API
 ****************************************************/
u32 ifcanSend(u8 whichCan,u8 destId,u8 packageType,u8 *pData,u16 length)
{
	
	struct item *itemToSend;
	u8 *newBuf;
	u8 error;

	
	//whichCan-使用哪个CAN口，CAN0/CAN1
	if((whichCan!=CAN0)&&(whichCan!=CAN1))
	{
		IFCAN_LOG("ifcanSend: whichCan error!\r\n");
		return 6;
	}
	
	
	
	if(ifcanCase[whichCan].ifcanSendQueue==NULL)
	{
		IFCAN_LOG("ifcanSend: ifcan has not been initilized\r\n");
		return 1;
	}
	
	if(length>IFCAN_MAX_DATA_LENGTH)
	{
		IFCAN_LOG("ifcanSend: not supported length\r\n");
		return 2;
	}
	
	if((IFCAN_TYPE_DATA!=packageType)&&(IFCAN_TYPE_CMD!=packageType)&&(IFCAN_TYPE_ACK!=packageType)&&(IFCAN_TYPE_FIRMWARE!=packageType))
	{
		IFCAN_LOG("ifcanSend: packageType parameter not supported!\r\n");
		return 3;
	}
	
	//申请数据内存，比pData长度多申请2个字节，用于存放destId和packageType
	itemToSend=item_alloc(ifcanCase[whichCan].ifcanSendQueue,pData,length+2,NULL);
	
	//内存申请失败
	if(itemToSend==NULL)
	{
		IFCAN_LOG("ifcanSend: itemToSend memory allocated failed!\r\n");
		return 4;
	}
	
	
	newBuf=(u8 *)(itemToSend->data.iov_base);
	
	//分别附加上destId和packageType信息
	*(newBuf+length)=destId;
	*(newBuf+length+1)=packageType;
	
	//把数据节点插入发送队列
	//IFCAN_LOG("ifcanSend queue_push...\r\n");
	error=queue_push(ifcanCase[whichCan].ifcanSendQueue,itemToSend);
	if(error)
	{
		IFCAN_LOG("ifcanSend: queue_push  failed!\r\n");
		return 5;
	}	
	return 0;	
}

/*!***************************************************
 * 应用层对ifcan进行初始化
 * @param:	whichCan-使用哪个CAN口，CAN0/CAN1
			ifcanConfiguration-ifcan的配置结构体
 * @return: 0-成功
			其他-失败(参数错误则立刻返回、超时)
			1-发送队列创建失败
			2-whichCan参数错误
			3-已经初始化过，不能重复初始化
			4-消息兴趣表初始化失败

 * @note:	使用ifcan必须先调用此函数，该函数必须在所有其他函数之前调用
 ****************************************************/
u32 ifcanInit(u8 whichCan,IfcanConfiguration ifcanConfiguration)
{	
	u32 ret,i,j;
	u8 whichCanUse;
	pthread_t prdIfcanSend,prdIfcanReceive;
	
	whichCanUse=whichCan;
	//whichCan-使用哪个CAN口，CAN0/CAN1
	if((whichCan!=CAN0)&&(whichCan!=CAN1))
	{
		IFCAN_LOG("ifcanInit: whichCan error!\r\n");
		return 2;
	}
	
	//不能重复初始化
	if(ifcanCase[whichCan].initializedFlag)
	{
		IFCAN_LOG("ifcanInit: this ifcanCase has already been initialized,reInitial would cause error!!!\r\n");
		return 3;
	}

	//1.参数初始化
	ifcanCase[whichCan].ifcanConfigurationGolbal.encryptEnable=ifcanConfiguration.encryptEnable;
	ifcanCase[whichCan].ifcanConfigurationGolbal.validateEnable=ifcanConfiguration.validateEnable;
	ifcanCase[whichCan].ifcanConfigurationGolbal.sourceId=ifcanConfiguration.sourceId;
	ifcanCase[whichCan].can_s=-1;
	
	//2.发送队列初始化
	ifcanCase[whichCan].ifcanSendQueue=queue_create();
	
	if(ifcanCase[whichCan].ifcanSendQueue==NULL)
	{
		IFCAN_LOG("ifcanInit:ifcanCase[whichCan].ifcanSendQueue create failed\r\n");
		return 1;
	}
	
	//3.创建发送线程
	ret=pthread_create(&prdIfcanSend,NULL,threadIfcanSend,&whichCanUse);
	if(ret!=0)
	{
		IFCAN_LOG("ifcanInit:threadIfcanSend create failed\r\n");
		return 1;
	}
	
	//4.创建接收线程
	IFCAN_LOG("ifcanInit:whichCanUse=%d\r\n",whichCanUse);
	ret=pthread_create(&prdIfcanReceive,NULL,threadIfcanReceive,&whichCanUse);
	
	//消息兴趣表初始化
	
	//1.初始化消息兴趣表操作信号量
	ret=pthread_mutex_init(&ifcanCase[whichCan].msgRegTableMutex,NULL);
	if(ret)
	{
		IFCAN_LOG("ifcanInit:pthread_mutex_init failed\r\n");
		return 4;
	}
	
	//2.各线程消息兴趣表初始化
	for(i=0;i<IFCAN_MAX_REG_THREADS;i++)
	{	
		//清除所有兴趣点标识
		for(j=0;j<IFCAN_MAX_REG_MSG_PER_THREAD;j++)
		{
			ifcanCase[whichCan].ifcanMsgRegTable[i].msgId[j]=0;
		}
		//兴趣点数量清零
		ifcanCase[whichCan].ifcanMsgRegTable[i].msgIdCnt=0;
		// pFlag标志清零
		ifcanCase[whichCan].ifcanMsgRegTable[i].pFlag=0;
		//清理消息队列
		if(ifcanCase[whichCan].ifcanMsgRegTable[i].msgQueueForThread!=NULL)
		{
			queue_destroy(ifcanCase[whichCan].ifcanMsgRegTable[i].msgQueueForThread);
		}
		//线程占用清零
		ifcanCase[whichCan].ifcanMsgRegTable[i].tid=0;
	}//for(i=0;i<IFCAN_MAX_REG_THREADS;i++)
		
	//设置被初始化标志
	ifcanCase[whichCan].initializedFlag=1;
}

/*!***************************************************
 * 应用层从ifcan底层接收数据,所接收的数据具有一般性
 * @param:   	whichCan-使用哪个CAN口，CAN0/CAN1
				source-用于返回消息源节点ID
				pData-数据缓存区
				pLength-用于返回数据区长度
				nSecond-阻塞的秒数，若nMs=0，则无限阻塞

 * @return:  	0-成功
				1-whichCan参数错误
				2-该线程尚未注册过消息兴趣点
				3-接收队列初始化异常，无法使用
				4-超时

 * @note: 		该函数为应用程序接口,若无底层数据，则阻塞相应的时间后退出。
 ****************************************************/
u32 ifcanReceive(u8 whichCan,u8 *pSource,u8 *pPackageType, u8 *pData, u32 *pLength, u32 nSecond)
{
	u32 i,j,k,currentThreadNodePos;
	
	u32 *pmsgIdBuf;
	
	pthread_t tid;
	
	struct item *ifcanDataItem;
	
	IfcanAppMsg *pAppMsg;
	
	//whichCan-使用哪个CAN口，CAN0/CAN1
	if((whichCan!=CAN0)&&(whichCan!=CAN1))
	{
		IFCAN_LOG("ifcanReceive: whichCan error!\r\n"); 
		return 1;
	}
	
	//获取调用线程id
	tid=pthread_self();
	
	for(i=0;i<IFCAN_MAX_REG_THREADS;i++)
	{
		//查看该线程是否有注册过MsgId
		if(ifcanCase[whichCan].ifcanMsgRegTable[i].tid==tid)
		{
			break;
		}
	}//for(i=0;i<IFCAN_MAX_REG_THREADS;i++)
	
	//该线程尚未注册过msgId
	if(i==IFCAN_MAX_REG_THREADS)
	{
		IFCAN_LOG("ifcanReceive: the current thread has not registed for any msgId!\r\n");
		return 2;
	}
	else
	{
		currentThreadNodePos=i;		
	}	
	
	if(ifcanCase[whichCan].ifcanMsgRegTable[currentThreadNodePos].msgQueueForThread==NULL)
	{
		IFCAN_LOG("ifcanReceive: ifcanCase[%d].ifcanMsgRegTable[%d].msgQueueForThread==NULL！\r\n",whichCan,currentThreadNodePos);
		return 3;
	}

	//阻塞等待消息，直到超时或收到消息

	ifcanCase[whichCan].ifcanMsgRegTable[currentThreadNodePos].pFlag=1;
	ifcanDataItem=queue_pop(ifcanCase[whichCan].ifcanMsgRegTable[currentThreadNodePos].msgQueueForThread,nSecond);
	
	//超时
	if(ifcanDataItem==NULL)
	{
		IFCAN_LOG("ifcanReceive: time out\r\n",whichCan,currentThreadNodePos);
		return 4;
	}
	
	IFCAN_LOG("received a msg\r\n");

	//ifcanDataItem 中解析出业务层数据
	pAppMsg=(IfcanAppMsg *)ifcanDataItem->data.iov_base;
	
	//复制数据到业务层缓存区
	for(i=0;i<pAppMsg->dataLength;i++)
	{
		pData[i]=pAppMsg->dataBuf[i];
	}
	
	//设置相关值
	*pSource=pAppMsg->sourceId;
	*pLength=pAppMsg->dataLength;
	*pPackageType=pAppMsg->packageType;
	
	//释放 ifcanDataItem 内存
	item_free(ifcanCase[whichCan].ifcanMsgRegTable[currentThreadNodePos].msgQueueForThread,ifcanDataItem);
	return 0;
}

/*!***************************************************
 * 应用层注册ifcan消息
 * @param:   	whichCan-使用哪个CAN口，CAN0/CAN1
				packageType-注册消息的包类型 IFCAN_TYPE_DATA/IFCAN_TYPE_CMD/IFCAN_TYPE_ACK/IFCAN_TYPE_FIRMWARE
				funCodeList-功能码集合数组
				funCodeCnt-功能码集合数组中的数量
 * @return:  	0-成功
 				1-whichCan参数错误
				2-未初始化，无法注册
				3-消息列表中包含被其他线程注册的消息
				4-没有可用兴趣节点
				5-接收队列初始化失败
				6-线程兴趣消息数量超过上限
				其他-参数错误
 * @note: 		同一线程可以调用多次,同一线程重复注册同一msgId不会引起错误，相当于后几次的重复注册无实际效果
 ****************************************************/
u32 ifcanMsgReg(u8 whichCan,u8 packageType,u16 *funCodeList,u16 funCodeCnt)
{
	u32 i,j,k,currentThreadNodePos,currentMsgIdPos;
	
	u32 pmsgIdBuf[IFCAN_MAX_REG_MSG_PER_THREAD];
	
	pthread_t tid;
	
	//获取调用线程id
	tid=pthread_self();
	
	
	
	//whichCan-使用哪个CAN口，CAN0/CAN1
	if((whichCan!=CAN0)&&(whichCan!=CAN1))
	{
		IFCAN_LOG("ifcanMsgReg: whichCan error!\r\n");
		return 1;
	}
	
	if((funCodeList==NULL)||(funCodeCnt==0)||(packageType>3))
	{
		IFCAN_LOG("ifcanMsgReg: parameter error!\r\n");
		return 7;
	}
	
	
	//若该ifcanCase尚未初始化，则直接返回错误
	if(!ifcanCase[whichCan].initializedFlag)
	{
		IFCAN_LOG("ifcanMsgReg: ifcanCase[can%d] has not been initialized!\r\n",whichCan);
		return 2;
	}
	
	for(i=0;i<funCodeCnt;i++)
	{
		pmsgIdBuf[i]=funCodeList[i]|((0x03&packageType)<<16);
	}

	
	//锁住互斥锁
	pthread_mutex_lock(&ifcanCase[whichCan].msgRegTableMutex);
	
	//在现有消息兴趣表中查找该msgId是否被注册
	for(k=0;k<funCodeCnt;k++)
	{
		for(i=0;i<IFCAN_MAX_REG_THREADS;i++)
		{
			for(j=0;j<IFCAN_MAX_REG_MSG_PER_THREAD;j++)
			{
				//在表中查找到已经注册过的msgId
				if(ifcanCase[whichCan].ifcanMsgRegTable[i].msgId[j]==pmsgIdBuf[k])
				{
					//1.查看该节点所处线程，是否是本线程,如果是，则继续循环,否则返回错误
					if(ifcanCase[whichCan].ifcanMsgRegTable[i].tid==tid)
					{
						//设置为0，以表示无效(已添加过，不需要再次添加)
						pmsgIdBuf[k]=0x00;						
						continue;
					}
					else
					{
						IFCAN_LOG("ifcanMsgReg:duplicate msgId is not allowed for different threads!\r\n");
						pthread_mutex_unlock(&ifcanCase[whichCan].msgRegTableMutex);
						return 3;
					}
				}//if(ifcanCase[whichCan].ifcanMsgRegTable[i].msgId[j]==pmsgIdBuf[k])
			}//for(j=0;j<IFCAN_MAX_REG_MSG_PER_THREAD;j++)
		}//for(i=0;i<IFCAN_MAX_REG_THREADS;i++)
	}//for(k=0;k<funCodeCnt;k++)
	

	//先找本线程对应的兴趣节点，若找不到，则找空余节点
	for(i=0;i<IFCAN_MAX_REG_THREADS;i++)
	{
		if(ifcanCase[whichCan].ifcanMsgRegTable[i].tid==tid)
		{
			break;
		}
	}
		
	//未找到本线程占用的兴趣节点
	if(i==IFCAN_MAX_REG_THREADS)
	{		

		//占用第一个空余兴趣节点
		for(i=0;i<IFCAN_MAX_REG_THREADS;i++)
		{
			if(ifcanCase[whichCan].ifcanMsgRegTable[i].tid==0)
			{
				break;
			}
		}
		
		//所有兴趣节点都已被占
		if(i==IFCAN_MAX_REG_THREADS)
		{
			IFCAN_LOG("ifcanMsgReg:No ifcanMsgRegTable Row is available\r\n");
			pthread_mutex_unlock(&ifcanCase[whichCan].msgRegTableMutex);
			return 4;
		}
		
		currentThreadNodePos=i;
		
		//进行一些第一次获得兴趣节点时必要的初始化工作
		
		//1.使用本线程占用该节点(节点tid=本线程tid)
		ifcanCase[whichCan].ifcanMsgRegTable[i].tid=tid;
		//2.接收队列初始化
		ifcanCase[whichCan].ifcanMsgRegTable[i].msgQueueForThread=queue_create();
		if(ifcanCase[whichCan].ifcanMsgRegTable[i].msgQueueForThread==NULL)
		{
			IFCAN_LOG("ifcanMsgReg:msgQueueForThread created failed!\r\n");
			pthread_mutex_unlock(&ifcanCase[whichCan].msgRegTableMutex);
			return 5;
		}
		ifcanCase[whichCan].ifcanMsgRegTable[i].msgIdCnt=0;
		
	}
	else
	{
		currentThreadNodePos=i;
	}
	
		
	
	currentMsgIdPos=ifcanCase[whichCan].ifcanMsgRegTable[currentThreadNodePos].msgIdCnt;

	for(k=0;k<funCodeCnt;k++)
	{
		//该Msg尚未被添加到兴趣表中
		if(pmsgIdBuf[k]!=0x00)
		{
			if(currentMsgIdPos<IFCAN_MAX_REG_MSG_PER_THREAD)
			{
				
				ifcanCase[whichCan].ifcanMsgRegTable[currentThreadNodePos].msgId[currentMsgIdPos++]=pmsgIdBuf[k];
				ifcanCase[whichCan].ifcanMsgRegTable[currentThreadNodePos].msgIdCnt=currentMsgIdPos;
			}
			else
			{
				IFCAN_LOG("ifcanMsgReg:too much msgId for a single thread\r\n");
				pthread_mutex_unlock(&ifcanCase[whichCan].msgRegTableMutex);
				return 6;
			}
		}
	}
	
	pthread_mutex_unlock(&ifcanCase[whichCan].msgRegTableMutex);
	return 0;
}
