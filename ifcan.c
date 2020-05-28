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
 * ��can id�н��������а�����can֡��Ϣ
 * @param:   	canId-��can�ײ���յ���can29λId
				pInfo-���ڴ�Ž�������֡��Ϣ
 * @return:  	0-�ɹ�
				����-ʧ��
 * @note: 		��ifcanProcess�����е���
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
 * ���ݹ�Կ��˽Կ��can 8�ֽ����ݽ��н���
 * @param:   	publicKey-8λ��Կ
				privateKey-8λ˽Կ
				primaryData-ԭ������
				resData-���ڴ�Ž��ܺ������
 * @return:  	0-�ɹ�
				����-ʧ��
 * @note: 		��ifcanProcess�����е���,һ�ν��ܲ���Ϊ8�ֽ����ݣ���������/ɾ��
 ****************************************************/
static u32 ifcanDecode(u8 publicKey, u8 privateKey, const u8 *primaryData, u8 *resData)
{
    u8 factor, i;

    if(resData == NULL)
    {
        IFCAN_LOG("ifcanDecode:resData==null!\r\n");
        return -1;
    }

    //��������
    factor = publicKey ^ privateKey;

    for(i = 0; i < 8; i++)
    {
        *(resData + i) = primaryData[i] ^ factor;
    }

    return 0;
}

/*!***************************************************
 * ifcan��֤
 * @param:
 * @return:  	0-�ɹ�
				����-ʧ��
 * @note: 		��ifcanProcess�����е���
 ****************************************************/
static u32 ifcanValidate(void)
{
    //������...
    return 0;
}

/*!***************************************************
 * ��ȡϵͳʱ�������λΪ��
 * @param:
 * @return:  	ʱ��� ��
 * @note:
 ****************************************************/
static u64  ifcanGetTimestampInSeconds()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec;
}

/*!***************************************************
 * ifcan��Ƭ������
 * @param:   	sourceId-��ϢԴId
				pData-8�ֽ�������
 * @return:  	0-�ɹ�
				1-δ���ҵ����ó�������ڵ�
				2-�ϰ�������
 * @note: 		��ifcanProcess�����е���,ÿ��ֻ����8�ֽ�,��������ɾ��
 ****************************************************/
static u32 ifcanSplitPackageProcess(u8 whichCan,u8 packageType, u8 sourceId, u8 *pData)
{
    u32 i;

    u8 nodeAvailable = 0;

    u32 existNodePos, currentPosInNode;

    u8 currentFrameCnt;

    u64 timeStamp;


    currentFrameCnt = pData[0] & 0x7F;

    //1.���ж��Ƿ��ǵ�1��
    //����ǵ�һ����1.������л��棻2.�����½ڵ�
    if(currentFrameCnt == 0x00)
    {
        //�������ýڵ�֮ǰ�������ʱ�ڵ�
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
            //ͬԴ������ʹ����
            if((sourceId == ifcanCase[whichCan].ifcanLongPackageNode[i].sourceId) && (1 == ifcanCase[whichCan].ifcanLongPackageNode[i].inUse))
            {
                ifcanClearLongPackageNode(whichCan,i);
                break;
            }
        }

		//�ӵ�0���ڵ㿪ʼ�������ýڵ�
		for(i=0;i<IFCAN_LONG_PACKAGE_MAX_CNT;i++)
		{
			if(0 == ifcanCase[whichCan].ifcanLongPackageNode[i].inUse)
			{
				ifcanCase[whichCan].lastLongPackageNodePos = i;
				nodeAvailable = 1;
				break;
			}
		}
    

        //δ���ҵ����ýڵ�
        if(0 == nodeAvailable)
        {
            IFCAN_LOG("ifcanSplitPackageProcess: No long package buffer node available!\r\n");
            return 1;
        }


		//���õ�ǰ�ڵ��sourceId
		ifcanCase[whichCan].ifcanLongPackageNode[ifcanCase[whichCan].lastLongPackageNodePos].sourceId=sourceId;
        //ռ���������Ŀ��ýڵ㣬�������ݸ��Ƶ��仺����
        ifcanCase[whichCan].ifcanLongPackageNode[ifcanCase[whichCan].lastLongPackageNodePos].inUse = 1;
        for(i = 0; i < 7; i++)
        {
            ifcanCase[whichCan].ifcanLongPackageNode[ifcanCase[whichCan].lastLongPackageNodePos].dataBuf[i] = pData[i + 1];
        }

        //���¿�д��λ��
        ifcanCase[whichCan].ifcanLongPackageNode[ifcanCase[whichCan].lastLongPackageNodePos].currentPos = 7;

        //���½ڵ�ʱ���
        ifcanCase[whichCan].ifcanLongPackageNode[ifcanCase[whichCan].lastLongPackageNodePos].timeStamp = ifcanGetTimestampInSeconds();

        return 0;

    }//if(currentFrameCnt==0x00)
    else	//������ǵ�һ���������нڵ��в���ͬԴ�ڵ�
    {
        for(i = 0; i < IFCAN_LONG_PACKAGE_MAX_CNT; i++)
        {
            if(		(1 == ifcanCase[whichCan].ifcanLongPackageNode[i].inUse)					//����ʹ����
                    &&	(sourceId == ifcanCase[whichCan].ifcanLongPackageNode[i].sourceId)		//ͬԴ
                    &&	((currentFrameCnt * 7) == ifcanCase[whichCan].ifcanLongPackageNode[i].currentPos)	//��������
              )
            {
                break;
            }
        }

        //δ�ҵ���sourceId���豸֮ǰ����Ϣ���棬�򷵻�ʧ��
        if(IFCAN_LONG_PACKAGE_MAX_CNT == i)
        {
            IFCAN_LOG("ifcanSplitPackageProcess:Illegal Long Package Frame Data\r\n");
            return 2;
        }

        existNodePos = i;
        currentPosInNode = ifcanCase[whichCan].ifcanLongPackageNode[i].currentPos;

        //��������
        for(i = 0; i < 7; i++)
        {
            ifcanCase[whichCan].ifcanLongPackageNode[existNodePos].dataBuf[currentPosInNode + i] = pData[i + 1];
        }

        //���¿�д��λ��
        ifcanCase[whichCan].ifcanLongPackageNode[existNodePos].currentPos += 7;


        //�Ƿ����һ֡?
        if((pData[0] >> 7) != 0x00)
        {
        	ifcanCase[whichCan].ifcanLongPackageNode[existNodePos].dataLength = ifcanCase[whichCan].ifcanLongPackageNode[existNodePos].currentPos;
            //֪ͨӦ�ò��������
       		ifcanPushData(
			whichCan,
			packageType,
			sourceId,
			ifcanCase[whichCan].ifcanLongPackageNode[existNodePos].dataBuf,
			ifcanCase[whichCan].ifcanLongPackageNode[existNodePos].dataLength);

			//����ڵ��ռ��
			ifcanCase[whichCan].ifcanLongPackageNode[existNodePos].inUse=0;
			ifcanCase[whichCan].ifcanLongPackageNode[existNodePos].currentPos=0;
			ifcanCase[whichCan].ifcanLongPackageNode[existNodePos].dataLength=0;
        }

        return 0;

    }//if(pData[0]==0x00) else {...}
}

/*!***************************************************
 * ifcanLongPackageNode���
 * @param:   	pos-��Ҫ����Ľڵ�λ��
 * @return:		0-�ɹ�
				1-λ�ó���
 * @note:
 ****************************************************/
static u32 ifcanClearLongPackageNode(u8 whichCan,u16 pos)
{

    u32 i;
    //1.�ж�λ���Ƿ�Ϸ�
    if(pos >= IFCAN_LONG_PACKAGE_MAX_CNT)
    {
        IFCAN_LOG("ifcanClearLongPackageNode:pos=%d exceed the Max NUM %d\r\n", pos, IFCAN_LONG_PACKAGE_MAX_CNT);
        return 1;
    }

    //2.���������
    for(i = 0; i < 896; i++)
    {
        ifcanCase[whichCan].ifcanLongPackageNode[pos].dataBuf[i] = 0x00;
    }
    //3.���ռ�ñ�־
    ifcanCase[whichCan].ifcanLongPackageNode[pos].inUse = 0;
    ifcanCase[whichCan].ifcanLongPackageNode[pos].currentPos = 0;
    ifcanCase[whichCan].ifcanLongPackageNode[pos].dataLength = 0;
}

/*!***************************************************
 * �Դ�CAN�ײ���յ���29λID��8�ֽ�����������
 * @param:   	canId-��can�ײ���յ���can29λId
				-���ڴ�Ž�������֡��Ϣ
 * @return:  	0-�ɹ�
				����-ʧ��
 * @note: 		�ڵײ���յ�can����ʱ���ñ�����
 ****************************************************/
static u32 ifcanProcess(u8 whichCan,u32 canId, u8 *pData)
{
    //���ڴ�ű�֡can��Ϣ29λId�а�������Ϣ
    IfcanIdInfo ifcanIdInfo;
    //���ڷ��ش�����
    u32 err, i;

    //��Ž��ܺ������
    u8 canFrameData[8];


    //1.������ ֡���͡���Ƭ��־�����ܱ�־����֤��־��Դ�ڵ��ַ����Կ
    err = ifcanIdParse(canId, &ifcanIdInfo);
    if(err != 0)
    {
        IFCAN_LOG("ifcanIdParse returned error,err=%d\r\n", err);
        return err;
    }

    //2.����
    if(1 == ifcanIdInfo.encryptFlag)
    {
        //����֮������ݴ���� canFrameData
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

    //3.��֤
    if(1 == ifcanIdInfo.validateFlag)
    {
        err = ifcanValidate();
        if(err != 0)
        {
            IFCAN_LOG("ifcanValidate returned error,err=%d\r\n", err);
            return err;
        }
    }

    //��Ƭ����
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
		//֪ͨӦ�ò�������
        ifcanPushData(whichCan,ifcanIdInfo.frameType,ifcanIdInfo.sourceId,canFrameData,8);
    }
}






/*!***************************************************
 * ��can�ײ��յ����������͵���Ӧ�̵߳Ľ��ն���
 * @param:   	whichCan-ʹ���ĸ�CAN�ڣ�CAN0/CAN1
				packageType-������
				sourceId-��ϢԴId
				pData-���ݻ�����
				dataLength-��Ч���ݳ���
				
 * @return:  	0-�ɹ�
				1-û����Ȥ�߳����ڵȴ�����Ϣ
				2-���нڵ��ȡʧ��
 * @note: 		�ڵײ���յ�can����ʱ���ñ�����
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

	//���� packageType �� pData[1] pData[2] ����ƥ��� �߳���Ȥ��
	if((packageType==IFCAN_TYPE_DATA)||(packageType==IFCAN_TYPE_ACK))
	{
		for(i=0;i<IFCAN_MAX_REG_THREADS;i++)
		{
			for(j=0;j<IFCAN_MAX_REG_MSG_PER_THREAD;j++)
			{
				//��ƥ�� packageType�� ��ƥ��funCode
				
				if((((ifcanCase[whichCan].ifcanMsgRegTable[i].msgId[j])>>16)&(0x0003))==packageType)
				{
					
					//���ն�����������pFlag=1
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
				//ƥ������msgId
				if((ifcanCase[whichCan].ifcanMsgRegTable[i].msgId[j])==msgId)//ɾ��������16
				{
          
					//���ն�����������pFlag=1
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
	//������Ӧ���ն���
	queue_push(q,ifcanAppMsgItem);
}

/*!***************************************************
 * CAN�ײ㷢���߳�
 * @param:   	arg-�̴߳���ʱ������Ĳ���
 * @return:  	
 * @note: 		�ú������᷵��
 ****************************************************/
static void *threadIfcanSend(void *arg)       
{
	struct item *itemToSend;
	
	u8 destId,packageType;

	u32 i;
	
	u8 whichCan=*(u8 *)arg;
	
	//whichCan-ʹ���ĸ�CAN�ڣ�CAN0/CAN1
	if((whichCan!=CAN0)&&(whichCan!=CAN1))
	{
		IFCAN_LOG("threadIfcanSend: whichCan error!\r\n");
		return NULL;
	}
	

	while(1)
	{
		//�Ӷ�����ȡ��һ�������͵����ݽڵ�
		
		itemToSend=queue_pop(ifcanCase[whichCan].ifcanSendQueue,0);
		if(itemToSend!=NULL)
		{
			//���������������ݣ����÷��ͺ���
			
			destId=*((u8 *)(itemToSend->data.iov_base+itemToSend->data.iov_len-2));
			packageType=*((u8 *)itemToSend->data.iov_base+itemToSend->data.iov_len-1);

			ifcanLowLayerSend(whichCan,destId,packageType,itemToSend->data.iov_base,itemToSend->data.iov_len-2);
			
			//�ͷŸýڵ��ڴ�
			item_free(ifcanCase[whichCan].ifcanSendQueue,itemToSend);
		}
	}
    
    return NULL;
}



/*!***************************************************
 * CAN�ײ�����߳�
 * @param:   	arg-�̴߳���ʱ������Ĳ���
 * @return:  	
 * @note: 		�ú������᷵��
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
  
    ifcanCase[whichCan].can_s=socket(PF_CAN, SOCK_RAW, CAN_RAW); //�����׽���
	
	
	if(ifcanCase[whichCan].can_s<0)
	{
		while(1)
		{
			IFCAN_LOG("threadIfcanReceive: socket returned error,can socket create failed!\r\n");
			sleep(1);
		}
	}
		


    ioctl(ifcanCase[whichCan].can_s, SIOCGIFINDEX, &ifcanCase[whichCan].ifr); //ָ�� can �豸
	addr.can_family = AF_CAN;
	
	addr.can_ifindex = ifcanCase[whichCan].ifr.ifr_ifindex;
	
	bind(ifcanCase[whichCan].can_s, (struct sockaddr *)&addr, sizeof(addr)); //���׽����� can0 ��
	
	rfilter[0].can_id = (ifcanCase[whichCan].ifcanConfigurationGolbal.sourceId)<<8;
	
	rfilter[0].can_mask = 0x00007F00;
  
	//���ù��˹���
	setsockopt(ifcanCase[whichCan].can_s, SOL_CAN_RAW, CAN_RAW_FILTER, &rfilter, sizeof(rfilter));
    int i; 
	while(1)
    {
		nbytes = read(ifcanCase[whichCan].can_s, &frame, sizeof(frame)); //���ձ���
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
 * CAN�ײ㷢�ͺ���
 * @param:   	whichCan-ʹ���ĸ�CAN�ڣ�CAN0/CAN1
				destId-Ŀ��Id
				packageType-������
				pData-���ݻ������׵�ַ
				length-ҵ�����Ҫ���͵������ܳ���
 * @return:  	
				0-�ɹ�
				1-whichCan��������
 * @note: 		�ú������������Ϊ����֮ǰ����������
 ****************************************************/
static u32 ifcanLowLayerSend(u8 whichCan,u8 destId,u8 packageType,u8 *pData,u16 length)
{	
	//ifcan �ְ�������
	static u8 splitBuf[IFCAN_MAX_DATA_LENGTH+(IFCAN_MAX_DATA_LENGTH/7)];
	
	u8 factor,timeStamp,totalFrameCount;
	u16 i,j,totalLength;
	
	
	//whichCan-ʹ���ĸ�CAN�ڣ�CAN0/CAN1
	if((whichCan!=CAN0)&&(whichCan!=CAN1))
	{
		IFCAN_LOG("ifcanLowLayerSend: whichCan error!\r\n");
		return 1;
	}
	
	if(length>8)
	{
		//������֡��
		totalFrameCount=length/7;
		if(length%7!=0)
		{
			totalFrameCount+=1;
		}

		//1.�ְ�,��������������7�ֽ�Ϊ��λ�ֳɶΣ����ڸ���֮ǰ���������
		for(j=0;j<totalFrameCount;j++)
		{
			//�Ѹ�֡���������ŵ�λ��
			splitBuf[j*8]=j;
			
			for(i=7*j;i<7*j+7;i++)
			{
				splitBuf[i+j+1]=pData[i];
				
				//����ԭʼ���ȣ������һ����δ������Ҫ��0
				if(i>=length)
				{
					splitBuf[i+j+1]=0x00;
				}
			}
		}
		//���һ֡��������λ��1����ʾβ֡
		j--;
		splitBuf[j*8]|=0x80;
		
		//�ܳ���
		totalLength=(j+1)*8;
		
		ifcanHardwareTransmit(whichCan,destId,packageType,splitBuf,totalLength);
	}
	else
	{
		//�������<=8,��
		ifcanHardwareTransmit(whichCan,destId,packageType,pData,length);
	}
	return 0;
}

/*!***************************************************
 * CAN�ײ㷢�ͺ���
 * @param:   	whichCan-ʹ���ĸ�CAN�ڣ�CAN0/CAN1
				destId-Ŀ��Id
				packageType-������
				pData-���ݻ������׵�ַ
				length-CAN�ײ���Ҫ���͵������ܳ��ȣ�������Ƭ����ֽڣ�
				
 * @return:  	0-�ɹ�
				1-whichCan ��������
				2-��Ӧ�� can socket ��δ����
				
 * @note: 		�ú������������Ϊ����֮ǰ����������
 ****************************************************/
static u32 ifcanHardwareTransmit(u8 whichCan,u8 destId,u8 packageType,u8 *pData,u16 length)
{
	u8 sendBuf[8];
	u32 canId=0;	
	u8 i,j;
	u8 timeStamp=ifcanGetTimestampInSeconds()%8;
	u8 factor;
	
	struct can_frame frame_tx;
	
			
	//whichCan-ʹ���ĸ�CAN�ڣ�CAN0/CAN1
	if((whichCan!=CAN0)&&(whichCan!=CAN1))
	{
		IFCAN_LOG("ifcanHardwareTransmit: whichCan error!\r\n");
		return 1;
	}
	
	//������
	canId|=packageType<<26;	
	
	//��Ƭ����־
	if(length>8)
	{
		canId|=1<<24;
	}
	
	//���ܱ�־
	if(ifcanCase[whichCan].ifcanConfigurationGolbal.encryptEnable)
	{
		canId|=1<<23;
	}
	
	//Դ��ַ
	canId|=ifcanCase[whichCan].ifcanConfigurationGolbal.sourceId<<15;
	//Ŀ�ĵ�ַ
	canId|=destId<<8;
	//��Կ��ʱ���-�룩
	canId|=timeStamp;
	
	//��������
	factor=timeStamp^IFCAN_PRIVATE_KEY;
		
	//ѭ����������
	i=0;
	do
	{
		for(j=0;j<8;j++)
		{
			sendBuf[j]=pData[i*8+j];
			
			//����������0
			if(j>length-1)
				sendBuf[j]=0;
			//�������ã����ü���
			if(ifcanCase[whichCan].ifcanConfigurationGolbal.encryptEnable)
				sendBuf[j]^=factor;
		}
		
		//����ϵͳ�ṩ��CAN���ͺ���
		
		
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
 * ifcan�������ݵ�API
 * @param:   	whichCan-ʹ���ĸ�CAN�ڣ�CAN0/CAN1
				destId-��Ҫ���͵�Ŀ�Ľڵ��ַ
				packageType-������ IFCAN_TYPE_DATA/IFCAN_TYPE_CMD/IFCAN_TYPE_ACK/IFCAN_TYPE_FIRMWARE
				pData-���ݻ�����
				length-���ݳ���
 * @return:  	0-�ɹ�
				1-ifcan��δ��ʼ��
				2-���ȹ���
				3-�����ʹ���
				4-�������ݽڵ��ڴ�����ʧ��
				5-�������ʧ��
				6-whichCan��������
				
 * @note: 		�ú�����Ӧ�ó���ͨ��ifcan�������ݵ�ΨһAPI
 ****************************************************/
u32 ifcanSend(u8 whichCan,u8 destId,u8 packageType,u8 *pData,u16 length)
{
	
	struct item *itemToSend;
	u8 *newBuf;
	u8 error;

	
	//whichCan-ʹ���ĸ�CAN�ڣ�CAN0/CAN1
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
	
	//���������ڴ棬��pData���ȶ�����2���ֽڣ����ڴ��destId��packageType
	itemToSend=item_alloc(ifcanCase[whichCan].ifcanSendQueue,pData,length+2,NULL);
	
	//�ڴ�����ʧ��
	if(itemToSend==NULL)
	{
		IFCAN_LOG("ifcanSend: itemToSend memory allocated failed!\r\n");
		return 4;
	}
	
	
	newBuf=(u8 *)(itemToSend->data.iov_base);
	
	//�ֱ𸽼���destId��packageType��Ϣ
	*(newBuf+length)=destId;
	*(newBuf+length+1)=packageType;
	
	//�����ݽڵ���뷢�Ͷ���
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
 * Ӧ�ò��ifcan���г�ʼ��
 * @param:	whichCan-ʹ���ĸ�CAN�ڣ�CAN0/CAN1
			ifcanConfiguration-ifcan�����ýṹ��
 * @return: 0-�ɹ�
			����-ʧ��(�������������̷��ء���ʱ)
			1-���Ͷ��д���ʧ��
			2-whichCan��������
			3-�Ѿ���ʼ�����������ظ���ʼ��
			4-��Ϣ��Ȥ���ʼ��ʧ��

 * @note:	ʹ��ifcan�����ȵ��ô˺������ú���������������������֮ǰ����
 ****************************************************/
u32 ifcanInit(u8 whichCan,IfcanConfiguration ifcanConfiguration)
{	
	u32 ret,i,j;
	u8 whichCanUse;
	pthread_t prdIfcanSend,prdIfcanReceive;
	
	whichCanUse=whichCan;
	//whichCan-ʹ���ĸ�CAN�ڣ�CAN0/CAN1
	if((whichCan!=CAN0)&&(whichCan!=CAN1))
	{
		IFCAN_LOG("ifcanInit: whichCan error!\r\n");
		return 2;
	}
	
	//�����ظ���ʼ��
	if(ifcanCase[whichCan].initializedFlag)
	{
		IFCAN_LOG("ifcanInit: this ifcanCase has already been initialized,reInitial would cause error!!!\r\n");
		return 3;
	}

	//1.������ʼ��
	ifcanCase[whichCan].ifcanConfigurationGolbal.encryptEnable=ifcanConfiguration.encryptEnable;
	ifcanCase[whichCan].ifcanConfigurationGolbal.validateEnable=ifcanConfiguration.validateEnable;
	ifcanCase[whichCan].ifcanConfigurationGolbal.sourceId=ifcanConfiguration.sourceId;
	ifcanCase[whichCan].can_s=-1;
	
	//2.���Ͷ��г�ʼ��
	ifcanCase[whichCan].ifcanSendQueue=queue_create();
	
	if(ifcanCase[whichCan].ifcanSendQueue==NULL)
	{
		IFCAN_LOG("ifcanInit:ifcanCase[whichCan].ifcanSendQueue create failed\r\n");
		return 1;
	}
	
	//3.���������߳�
	ret=pthread_create(&prdIfcanSend,NULL,threadIfcanSend,&whichCanUse);
	if(ret!=0)
	{
		IFCAN_LOG("ifcanInit:threadIfcanSend create failed\r\n");
		return 1;
	}
	
	//4.���������߳�
	IFCAN_LOG("ifcanInit:whichCanUse=%d\r\n",whichCanUse);
	ret=pthread_create(&prdIfcanReceive,NULL,threadIfcanReceive,&whichCanUse);
	
	//��Ϣ��Ȥ���ʼ��
	
	//1.��ʼ����Ϣ��Ȥ������ź���
	ret=pthread_mutex_init(&ifcanCase[whichCan].msgRegTableMutex,NULL);
	if(ret)
	{
		IFCAN_LOG("ifcanInit:pthread_mutex_init failed\r\n");
		return 4;
	}
	
	//2.���߳���Ϣ��Ȥ���ʼ��
	for(i=0;i<IFCAN_MAX_REG_THREADS;i++)
	{	
		//���������Ȥ���ʶ
		for(j=0;j<IFCAN_MAX_REG_MSG_PER_THREAD;j++)
		{
			ifcanCase[whichCan].ifcanMsgRegTable[i].msgId[j]=0;
		}
		//��Ȥ����������
		ifcanCase[whichCan].ifcanMsgRegTable[i].msgIdCnt=0;
		// pFlag��־����
		ifcanCase[whichCan].ifcanMsgRegTable[i].pFlag=0;
		//������Ϣ����
		if(ifcanCase[whichCan].ifcanMsgRegTable[i].msgQueueForThread!=NULL)
		{
			queue_destroy(ifcanCase[whichCan].ifcanMsgRegTable[i].msgQueueForThread);
		}
		//�߳�ռ������
		ifcanCase[whichCan].ifcanMsgRegTable[i].tid=0;
	}//for(i=0;i<IFCAN_MAX_REG_THREADS;i++)
		
	//���ñ���ʼ����־
	ifcanCase[whichCan].initializedFlag=1;
}

/*!***************************************************
 * Ӧ�ò��ifcan�ײ��������,�����յ����ݾ���һ����
 * @param:   	whichCan-ʹ���ĸ�CAN�ڣ�CAN0/CAN1
				source-���ڷ�����ϢԴ�ڵ�ID
				pData-���ݻ�����
				pLength-���ڷ�������������
				nSecond-��������������nMs=0������������

 * @return:  	0-�ɹ�
				1-whichCan��������
				2-���߳���δע�����Ϣ��Ȥ��
				3-���ն��г�ʼ���쳣���޷�ʹ��
				4-��ʱ

 * @note: 		�ú���ΪӦ�ó���ӿ�,���޵ײ����ݣ���������Ӧ��ʱ����˳���
 ****************************************************/
u32 ifcanReceive(u8 whichCan,u8 *pSource,u8 *pPackageType, u8 *pData, u32 *pLength, u32 nSecond)
{
	u32 i,j,k,currentThreadNodePos;
	
	u32 *pmsgIdBuf;
	
	pthread_t tid;
	
	struct item *ifcanDataItem;
	
	IfcanAppMsg *pAppMsg;
	
	//whichCan-ʹ���ĸ�CAN�ڣ�CAN0/CAN1
	if((whichCan!=CAN0)&&(whichCan!=CAN1))
	{
		IFCAN_LOG("ifcanReceive: whichCan error!\r\n"); 
		return 1;
	}
	
	//��ȡ�����߳�id
	tid=pthread_self();
	
	for(i=0;i<IFCAN_MAX_REG_THREADS;i++)
	{
		//�鿴���߳��Ƿ���ע���MsgId
		if(ifcanCase[whichCan].ifcanMsgRegTable[i].tid==tid)
		{
			break;
		}
	}//for(i=0;i<IFCAN_MAX_REG_THREADS;i++)
	
	//���߳���δע���msgId
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
		IFCAN_LOG("ifcanReceive: ifcanCase[%d].ifcanMsgRegTable[%d].msgQueueForThread==NULL��\r\n",whichCan,currentThreadNodePos);
		return 3;
	}

	//�����ȴ���Ϣ��ֱ����ʱ���յ���Ϣ

	ifcanCase[whichCan].ifcanMsgRegTable[currentThreadNodePos].pFlag=1;
	ifcanDataItem=queue_pop(ifcanCase[whichCan].ifcanMsgRegTable[currentThreadNodePos].msgQueueForThread,nSecond);
	
	//��ʱ
	if(ifcanDataItem==NULL)
	{
		IFCAN_LOG("ifcanReceive: time out\r\n",whichCan,currentThreadNodePos);
		return 4;
	}
	
	IFCAN_LOG("received a msg\r\n");

	//ifcanDataItem �н�����ҵ�������
	pAppMsg=(IfcanAppMsg *)ifcanDataItem->data.iov_base;
	
	//�������ݵ�ҵ��㻺����
	for(i=0;i<pAppMsg->dataLength;i++)
	{
		pData[i]=pAppMsg->dataBuf[i];
	}
	
	//�������ֵ
	*pSource=pAppMsg->sourceId;
	*pLength=pAppMsg->dataLength;
	*pPackageType=pAppMsg->packageType;
	
	//�ͷ� ifcanDataItem �ڴ�
	item_free(ifcanCase[whichCan].ifcanMsgRegTable[currentThreadNodePos].msgQueueForThread,ifcanDataItem);
	return 0;
}

/*!***************************************************
 * Ӧ�ò�ע��ifcan��Ϣ
 * @param:   	whichCan-ʹ���ĸ�CAN�ڣ�CAN0/CAN1
				packageType-ע����Ϣ�İ����� IFCAN_TYPE_DATA/IFCAN_TYPE_CMD/IFCAN_TYPE_ACK/IFCAN_TYPE_FIRMWARE
				funCodeList-�����뼯������
				funCodeCnt-�����뼯�������е�����
 * @return:  	0-�ɹ�
 				1-whichCan��������
				2-δ��ʼ�����޷�ע��
				3-��Ϣ�б��а����������߳�ע�����Ϣ
				4-û�п�����Ȥ�ڵ�
				5-���ն��г�ʼ��ʧ��
				6-�߳���Ȥ��Ϣ������������
				����-��������
 * @note: 		ͬһ�߳̿��Ե��ö��,ͬһ�߳��ظ�ע��ͬһmsgId������������൱�ں󼸴ε��ظ�ע����ʵ��Ч��
 ****************************************************/
u32 ifcanMsgReg(u8 whichCan,u8 packageType,u16 *funCodeList,u16 funCodeCnt)
{
	u32 i,j,k,currentThreadNodePos,currentMsgIdPos;
	
	u32 pmsgIdBuf[IFCAN_MAX_REG_MSG_PER_THREAD];
	
	pthread_t tid;
	
	//��ȡ�����߳�id
	tid=pthread_self();
	
	
	
	//whichCan-ʹ���ĸ�CAN�ڣ�CAN0/CAN1
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
	
	
	//����ifcanCase��δ��ʼ������ֱ�ӷ��ش���
	if(!ifcanCase[whichCan].initializedFlag)
	{
		IFCAN_LOG("ifcanMsgReg: ifcanCase[can%d] has not been initialized!\r\n",whichCan);
		return 2;
	}
	
	for(i=0;i<funCodeCnt;i++)
	{
		pmsgIdBuf[i]=funCodeList[i]|((0x03&packageType)<<16);
	}

	
	//��ס������
	pthread_mutex_lock(&ifcanCase[whichCan].msgRegTableMutex);
	
	//��������Ϣ��Ȥ���в��Ҹ�msgId�Ƿ�ע��
	for(k=0;k<funCodeCnt;k++)
	{
		for(i=0;i<IFCAN_MAX_REG_THREADS;i++)
		{
			for(j=0;j<IFCAN_MAX_REG_MSG_PER_THREAD;j++)
			{
				//�ڱ��в��ҵ��Ѿ�ע�����msgId
				if(ifcanCase[whichCan].ifcanMsgRegTable[i].msgId[j]==pmsgIdBuf[k])
				{
					//1.�鿴�ýڵ������̣߳��Ƿ��Ǳ��߳�,����ǣ������ѭ��,���򷵻ش���
					if(ifcanCase[whichCan].ifcanMsgRegTable[i].tid==tid)
					{
						//����Ϊ0���Ա�ʾ��Ч(����ӹ�������Ҫ�ٴ����)
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
	

	//���ұ��̶߳�Ӧ����Ȥ�ڵ㣬���Ҳ��������ҿ���ڵ�
	for(i=0;i<IFCAN_MAX_REG_THREADS;i++)
	{
		if(ifcanCase[whichCan].ifcanMsgRegTable[i].tid==tid)
		{
			break;
		}
	}
		
	//δ�ҵ����߳�ռ�õ���Ȥ�ڵ�
	if(i==IFCAN_MAX_REG_THREADS)
	{		

		//ռ�õ�һ��������Ȥ�ڵ�
		for(i=0;i<IFCAN_MAX_REG_THREADS;i++)
		{
			if(ifcanCase[whichCan].ifcanMsgRegTable[i].tid==0)
			{
				break;
			}
		}
		
		//������Ȥ�ڵ㶼�ѱ�ռ
		if(i==IFCAN_MAX_REG_THREADS)
		{
			IFCAN_LOG("ifcanMsgReg:No ifcanMsgRegTable Row is available\r\n");
			pthread_mutex_unlock(&ifcanCase[whichCan].msgRegTableMutex);
			return 4;
		}
		
		currentThreadNodePos=i;
		
		//����һЩ��һ�λ����Ȥ�ڵ�ʱ��Ҫ�ĳ�ʼ������
		
		//1.ʹ�ñ��߳�ռ�øýڵ�(�ڵ�tid=���߳�tid)
		ifcanCase[whichCan].ifcanMsgRegTable[i].tid=tid;
		//2.���ն��г�ʼ��
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
		//��Msg��δ����ӵ���Ȥ����
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
