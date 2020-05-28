/*!***************************************************
 * 测试程序
 * @param:
 * @return:
 * @note: 		开发过程中使用，代码完成后需要删除本函数
 ****************************************************/
#include <stdio.h>
#include <pthread.h>
#include <sys/time.h>

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>


#include "ifcan.h"

#include "lib/libmsc/qtts.h"
#include "lib/libmsc/msp_cmn.h"
#include "lib/libmsc/msp_errors.h"


FILE *firmwareFileSource;
FILE *firmwareFileDesti;
char filenameSource[128];
char filenameDesti[128];

unsigned long getFileSize(const char *path)
{
	unsigned long filesize = -1;	
	struct stat statbuff;
	if(stat(path, &statbuff) < 0){
		return filesize;
	}else{
		filesize = statbuff.st_size;
	}
	return filesize;
}

unsigned char CRC8(unsigned char *ptr,unsigned int len)
{
    unsigned char crc;
    unsigned char i;
    crc = 0;
	
    while(len--)
    {
       crc ^= *ptr++;
       for(i = 0;i < 8;i++)
       {
           if(crc & 0x80)
           {
               crc = (crc << 1) ^ 0x07;
           }
           else crc <<= 1;
       }
    }
    return crc;
}


void *firmwarePackageIfcanSend(void *arg)
{
	unsigned char destId=0x2;
	unsigned char packageType=IFCAN_TYPE_DATA;
	unsigned char ackType=IFCAN_TYPE_ACK;
	unsigned char source;
	unsigned char ackBuf[8];
	unsigned int ackLen;
	unsigned char whichCan=*(unsigned char *)arg;
	unsigned long filesize;
	
	char fileBuf[890];
	char sendBuf[896];
	unsigned char crc;
	unsigned int i;
	size_t sizeRead;
	unsigned short packageCnt;//包序号

	unsigned char retryCnt;
	unsigned char waitRes;
	unsigned char crcRes;

	unsigned short funCodeList[]={1};   //ifcan协议中数据帧、应答帧、固件帧都没有功能码，都注册1
	ifcanMsgReg(whichCan,IFCAN_TYPE_ACK,funCodeList,1);
	
	printf("send thread running\r\n");
	
	firmwareFileSource=fopen(filenameSource,"rb");
		
	
	printf(" *************** %s\r\n",filenameSource);
	printf(" *************** %p\r\n",firmwareFileSource);
	
	
	if(firmwareFileSource==NULL)
	while(1)
	{
		printf("file %s not exist\r\n",filenameSource);
		sleep(1);
	}
			

	filesize=getFileSize(filenameSource);
	
	printf("size of the %s is %ld \r\n ",filenameSource,filesize);
	
	packageCnt=0;
	do
	{			
		
		sizeRead=fread(fileBuf,1,890,firmwareFileSource);
				
		crc=CRC8(fileBuf,sizeRead);

		sendBuf[0]=0xFF;
		sendBuf[1]=0x0;//0表示不是最后一包，1表示最后一包
		
		if ((((filesize%890)==0)&&(packageCnt==((filesize/890)-1)))||(((filesize%890)!=0)&&(packageCnt==(filesize/890))))//数据包字节数是892的整数倍时 he 字节数不是892整数倍但，最后一包发送前的处理
			{
			sendBuf[1]=0x1;
			}

		//添加包序号
		sendBuf[2]=(packageCnt>>8)&0xFF;
		sendBuf[3]=packageCnt&0xFF;
		
		for (i = 0; i <sizeRead; i++)
			{
			sendBuf[i+4]=fileBuf[i];
			}

		sendBuf[sizeRead+4]=crc;
		sendBuf[sizeRead+5]=0xEE;//设数据帧的起始符为0xFF，结束符为0xEE
			
		printf("________read a  file package:sizeread=%d \r\n",sizeRead);
		
		
		retryCnt=0;
		
		while(retryCnt<5)
		{
			if (sizeRead!=0)
			{
				printf("retryCnt=%d____send the  %d  package:sizeread=%d \r\n",retryCnt,packageCnt,sizeRead);
				ifcanSend(whichCan,destId,packageType,sendBuf,sizeRead+6);
			}
			else
			{
				break;
			}
			
			waitRes=ifcanReceive(whichCan,&source,&ackType,ackBuf,&ackLen,1);
			
			if(waitRes==0)
			{
				crcRes=ackBuf[1];
			}
			
			retryCnt++;
			
			if((waitRes==0)&&(crcRes==0))//接收成功跳出重发循环
			{
				break;
			}
			else if((waitRes==0)&&(crcRes==2))//接收到重复包，跳出重发循环，发送下一包
			{
				break;
			}
			else if((waitRes==0)&&(crcRes==3))//接收最后一包成功，整个文件接收成功。跳出重发循环
			{
				break;
			}
		}
		
		if(retryCnt==5)
		{
			while(1)
			{
				printf("file send error\r\n");
				sleep(1);
			}				
		}
		
		packageCnt++;
	}while(!(sizeRead<890));

	printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@send firmwareFileSource over \r\n");
	fclose(firmwareFileSource);
}


/*!***************************************************
 * ifcan在线升级，固件帧传输
 * @param:		arg-线程创建时，传入的参数
 * @return: 	
 * @note:		该函数不会返回
 ****************************************************/

void *threadOnlineUpgrade(void *arg)
{
	unsigned char whichCan=*(unsigned char *)arg;
	unsigned char destId=0x1;
	unsigned char ret,source,packageType;
	unsigned char ackType=IFCAN_TYPE_ACK;
	unsigned int Length;
	unsigned char pData[896];
	unsigned char recvBuf[890];
	unsigned char ackBuf[8];
	unsigned int i,j,m;
	unsigned short foreignPackageCnt,localPackageCnt;//包序号
	unsigned char localCrc,foreignCrc;
	unsigned short funCodeList[]={1};   //ifcan协议中数据帧、应答帧、固件帧都没有功能码，都注册1
	ret=ifcanMsgReg(whichCan,IFCAN_TYPE_DATA,funCodeList,1);

	firmwareFileDesti=fopen(filenameDesti,"wb");
	if(firmwareFileDesti==NULL)
	{
		while(1)
		{
			printf("file %s create error!\r\n",filenameDesti);
			sleep(1);
		}
	}
	
	localPackageCnt=0;
	while(1)
	{
		ifcanReceive(whichCan,&source,&packageType,pData,&Length,0);
		printf("received a new file package\r\n");
		
		printf("received the first byte is pData[0]=%x \r\n",pData[0]);
		printf("received the last byte is pData[Length-1]=%x ，Length=%d \r\n",pData[Length-1],Length);
		
		
		if (pData[1]==1)//判断数据包的最后一包标志位，接收最后一包
			{
				//去掉尾帧补的i个0
				
					for (i = 0; i < 896; i++)
					{
						
						if(pData[Length-1-i]==0xEE)
						{
							printf("++++++++++=fwrite the last received package\r\n");
							
							printf("received the last package last byte  has %d ge 0  \r\n",i);
							for (j = 0; j <(Length-6-i); j++)
								{
								recvBuf[j]=pData[j+4];
								}

							foreignPackageCnt=(unsigned short)((pData[2]<<8)+pData[3]);
							
							foreignCrc=pData[Length-2-i];
							localCrc=CRC8(recvBuf,Length-i-6);

							printf("foreignCrc=======pData[Length-2]=%x\r\n",pData[Length-2-i]);//crc
							printf("localCrc=%x\r\n",localCrc);

								ackBuf[0]=0xff;
							
								ackBuf[2]=0xEE;
							if ((localCrc==foreignCrc)&&(localPackageCnt==foreignPackageCnt))
								{
									ackBuf[1]=0x3;//最后一包接收成功，整个文件接收完成
									fwrite(recvBuf,1,Length-i-6,firmwareFileDesti);
									localPackageCnt=foreignPackageCnt+1;
								}
							else{
									ackBuf[1]=0x1;
								}

							printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!sizeof(recvBuf)=%d  ackbuf[1]==%d\r\n",sizeof(recvBuf),ackBuf[1]);
							ifcanSend(whichCan,destId,ackType,ackBuf,3);
							
							fclose(firmwareFileDesti);
							while(1)
							{
								printf("file receive over！\r\n");
								sleep(1);
							}
						}
					}
			
			}
		else if(pData[1]==0)
			{
		
				for (i = 0; i < Length-6; i++)
					{
								
						recvBuf[i]=pData[i+4];
								
					}
				
				   foreignPackageCnt=(unsigned short)((pData[2]<<8)+pData[3]);
	
					foreignCrc=pData[Length-2];
					localCrc=CRC8(recvBuf,890);

					printf("foreignCrc=%x\r\n",foreignCrc);
					printf("localCrc=%x\r\n",localCrc);
					printf("foreignPackageCnt=%d\r\n",foreignPackageCnt);
					printf("localPackageCnt=%d\r\n",localPackageCnt);

					
						ackBuf[0]=0xff;
					
						ackBuf[2]=0xEE;


					if ((localCrc==foreignCrc)&&(localPackageCnt==foreignPackageCnt))
						{
							ackBuf[1]=0x0;//设0为接收成功，1为接收失败
							fwrite(recvBuf,1,Length-6,firmwareFileDesti);
							localPackageCnt=foreignPackageCnt+1;
				   
						}
					else if((localCrc==foreignCrc)&&(localPackageCnt==(foreignPackageCnt+1)))
						{
							ackBuf[1]=0x2;//当前包为重复包，请发下一包
							
						}
					else{
							ackBuf[1]=0x1;//接收失败
						}
					printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! ackbuf[1]==%d\r\n",ackBuf[1]);
					ifcanSend(whichCan,destId,ackType,ackBuf,3);
			}

	}
}


	
int main(int argc ,char ** argv)
{
	pthread_t pIfcanSend,pIfcanRecv;
	u8 whichCanUse0,whichCanUse1;
	u32 ret;
	whichCanUse0=CAN0;
	whichCanUse1=CAN1;
	
	
	if(argc!=3)
	{
		printf("usage:myapp sourceFileName destinationFileName\r\n");
		return -1;
	}
	
	
	
	sprintf(filenameSource,"%s",argv[1]);
	sprintf(filenameDesti,"%s",argv[2]);
	
		printf("----------------%s\r\n",filenameSource);
		printf("----------------%s\r\n",filenameDesti);


	

	IfcanConfiguration ifcanConfig;

	ifcanConfig.encryptEnable=0x1;//不加密
	ifcanConfig.validateEnable=0x0;
	ifcanConfig.sourceId=0x1;
	ifcanInit(CAN0,ifcanConfig);

	ifcanConfig.sourceId=0x2;
	ifcanInit(CAN1,ifcanConfig);
	
	


	
	//创建发送线程
	ret=pthread_create(&pIfcanSend,NULL,firmwarePackageIfcanSend,&whichCanUse0);


	//创建接收线程
	
	ret=pthread_create(&pIfcanRecv,NULL,threadOnlineUpgrade,&whichCanUse1);



	while(1)
		sleep(1);
	return 0;
}










