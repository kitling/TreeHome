#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <3ds.h>

#define hangmacro() (\
{\
    puts("Press a key to exit...");\
    while(aptMainLoop())\
    {\
        hidScanInput();\
        if(hidKeysDown())\
        {\
            goto killswitch;\
        }\
        gspWaitForVBlank();\
    }\
})

#define err(nth, wat) *((u32*)0x00100000+(nth))=wat;
#define ded(wat) err(0,wat)
#define die() ded(0xDEADBEEF);

// Yay Citra
int printk(const char *format, ...) {
    va_list args, args_copy;
    va_start(args, format);
    va_copy(args_copy, args);

    int size = vsnprintf(NULL, 0, format, args_copy) + 1;
    va_end(args_copy);

    char *buffer = malloc(size);
    vsnprintf(buffer, size, format, args);
    va_end(args);

    svcOutputDebugString(buffer, size);
    free(buffer);

    return size;
}

vu32 doit = 1;

static RecursiveLock srvLockHandle;

typedef void (*SignalHandler)(u32);
typedef struct
{
    u32 notificaton;
    SignalHandler func;
    void* next;
} SignalHook;

typedef struct
{
    u32 type;
    u32 appletUID;
    u64 titlePID;
    u32 unk[0xC];
} SysMenuArg;

SysMenuArg menuarg;

typedef enum
{
    MS_NONE,
    MS_IDLE,
    MS_LOADING1,
    MS_LOADING2,
    MS_APP_PAUSE,
    MS_APP_CLOSE,
    MS_CLEANING,
    MS_FIRST,
    MS_SCREENCAP
} MenuState;

MenuState ms = MS_NONE;

static Handle srvSemaphore = 0;
static Thread srvThread = 0;
static SignalHook srvRootHook;

static SignalHook aptRootHook;

void srvLock()
{
    Handle currhandle = *(((u32*)getThreadLocalStorage()) + 1);
    if(currhandle == srvLockHandle.thread_tag) return;
    RecursiveLock_Lock(&srvLockHandle);
}

void srvUnlock()
{
    Handle currhandle = *(((u32*)getThreadLocalStorage()) + 1);
    if(currhandle == srvLockHandle.thread_tag) return;
    RecursiveLock_Unlock(&srvLockHandle);
}

void srvHookSignal(u32 nid, SignalHandler func)
{
    if(!func) return;
    SignalHook* curr = &srvRootHook;
    while(curr->next) curr = curr->next;
    curr->next = malloc(sizeof(SignalHook));
    curr = curr->next;
    curr->next = 0;
    curr->notificaton = nid;
    curr->func = func;
}

void srvMainLoop(void* param)
{
    vu32* running = param;
    Result ret = 0;
    u32 NotificationID = 0;
    while(*running)
    {
        ret = svcWaitSynchronization(srvSemaphore, -1ULL);
        if(ret < 0) break;
        ret = srvReceiveNotification(&NotificationID);
        if(ret < 0) break;

        srvLock();
        SignalHook* curr = srvRootHook.next;
        while(curr)
        {
            if(curr->notificaton == NotificationID) curr->func(NotificationID);
            curr = curr->next;
        }
        srvUnlock();
    }
    if(*running) *(u32*)0x00100100 = ret;
}

void aptHookSignal(u32 nid, SignalHandler func)
{
    if(!func) return;
    SignalHook* curr = &aptRootHook;
    while(curr->next) curr = curr->next;
    curr->next = malloc(sizeof(SignalHook));
    curr = curr->next;
    curr->next = 0;
    curr->notificaton = nid;
    curr->func = func;
}

int aptCallEvent(APT_Signal sig)
{
    SignalHook* curr = aptRootHook.next;
    while(curr)
    {
        if(curr->notificaton == sig) curr->func(sig);
        curr = curr->next;
    }
    return 0;
}

Result APT_CancelLibraryApplet(u8 exit)
{
    u32 ipc[16];
    ipc[0] = 0x3B0040;
    ipc[1] = exit;
    return aptSendCommand(ipc);
}

Result APT_GetProgramIdOnApplicationJump(u64* current, FS_MediaType* currtype, u64* target, FS_MediaType* targettype)
{
    u32 ipc[16];
    ipc[0] = 0x330000;
    Result ret = aptSendCommand(ipc);
    if(ret < 0) return ret;
    if(current) *current = *(u64*)(&ipc[2]);
    if(currtype) *currtype = ipc[4];
    if(target) *target = *(u64*)(&ipc[5]);
    if(targettype) *targettype = ipc[7];
    return ret;
}

Result APT_PrepareToStartApplication(u64 titleid, FS_MediaType media, u32 flags)
{
    u32 ipc[16];
    ipc[0] = 0x150140;
    *(u64*)(&ipc[1]) = titleid;
    ipc[3] = media;
    ipc[4] = 0;
    ipc[5] = flags;
    return aptSendCommand(ipc);
}

Result APT_StartApplication(u8* param, size_t sizeofparam, u8* hmac, size_t sizeofhmac, u8 paused)
{
    u32 ipc[16];
    ipc[0] = 0x1B00C4;
    ipc[1] = sizeofparam;
    ipc[2] = sizeofhmac;
    ipc[3] = paused;
    ipc[4] = (sizeofparam << 14) | 2;
    ipc[5] = param;
    ipc[6] = (sizeofhmac << 14) | 0x802;
    ipc[7] = hmac;
    return aptSendCommand(ipc);
}

Result APT_LoadSysMenuArg(SysMenuArg* buf)
{
    u32 cmdbuf[16] = {0};
    cmdbuf[0] = 0x360040; // TODO: Use IPC_MakeHeader
    cmdbuf[1] = sizeof(SysMenuArg);

    u32 saved_threadstorage[2];
    u32* staticbufs = getThreadStaticBuffers();
    saved_threadstorage[0]=staticbufs[0];
    saved_threadstorage[1]=staticbufs[1];
    staticbufs[0] = IPC_Desc_StaticBuffer(cmdbuf[1], 0);
    staticbufs[1] = buf;

    Result ret = aptSendCommand(cmdbuf);
    staticbufs[0] = saved_threadstorage[0];
    staticbufs[1] = saved_threadstorage[1];

    return R_SUCCEEDED(ret) ? cmdbuf[1] : ret;
}

Result APT_StoreSysMenuArg(SysMenuArg* buf)
{
    u32 cmdbuf[16] = {0};
    cmdbuf[0] = 0x370042; // TODO: Use IPC_MakeHeader
    cmdbuf[1] = sizeof(SysMenuArg);
    cmdbuf[2] = IPC_Desc_StaticBuffer(cmdbuf[1], 0);
    cmdbuf[3] = buf;

    Result ret = aptSendCommand(cmdbuf);
    return R_SUCCEEDED(ret) ? cmdbuf[1] : ret;
}

void __appInit(void)
{
    Result res = 0;
    if((res = srvInit()) < 0) err(0xFF,res);
    RecursiveLock_Init(&srvLockHandle);
    //if((res = srvEnableNotification(&srvSemaphore)) < 0) ded(res);
    //srvThread = threadCreate(srvMainLoop, &doit, 0x1000, 0x18, -2, 0);

    if((res = nsInit()) < 0) err(1,res);
    if((res = ptmSysmInit()) < 0) err(2,res);
    if((res = psInit()) < 0) err(3,res);
    //if((res = aptInit(0x300, 1, 0, 0)) < 0) err(4,res);
    //aptExit();

    u32 aptattr = aptMakeAppletAttr(APTPOS_SYS, false, false) | 0x20000000;
    if((res = aptInitApplet(0 /*level*/, aptattr, 1 /*idk*/)) < 0) err(5,res);

    if((res = NS_LaunchTitle(0x0004013000001C02, 0, NULL)) < 0) err(10,res);//== 0xC8A12402) die();

    //if((res = gspInit()) < 0) ded(res);
    //GSPGPU_SetLcdForceBlack(0);
    //GSPGPU_AcquireRight(0);

    if((res = NS_LaunchTitle(0x0004013000001802, 0, NULL)) < 0) err(11,res);//== 0xC8A12402) die();
    if((res = NS_LaunchTitle(0x0004013000001D02, 0, NULL)) < 0) err(12,res);//== 0xC8A12402) die();
    if((res = NS_LaunchTitle(0x0004013000001A02, 0, NULL)) < 0) err(13,res);//== 0xC8A12402) die();
    if((res = NS_LaunchTitle(0x0004013000001502, 0, NULL)) < 0) err(14,res);//== 0xC8A12402) die();

    hidInit();

    fsInit();
    sdmcInit();
}

void __appExit(void)
{
    sdmcExit();
    fsExit();

    hidExit();

    //GSPGPU_ReleaseRight();
    //gspExit();

    aptExit();
    psExit();
    nsExit();
    srvExit();
}



int main()
{
  Result res = 0;
  // =====[PROGINIT]=====

  //extern u32 __ctru_linear_heap;
  //*(u32*)0x00100099 =  __ctru_linear_heap;
  gfxInit(GSP_RGBA8_OES, GSP_RGBA8_OES, false);
  //die();
  //extern u32 __ctru_linear_heap;
  //*(u32*)0x00100099 =  __ctru_linear_heap;
  consoleInit(GFX_BOTTOM, NULL);

  // Print out a few things to sanity-check the environment.
  puts("-- Checking environment --");
  printf("isHomebrew: %s\n", envIsHomebrew() ? "true" : "false"); // false
  printf("aptAppId: 0x%x\n", envGetAptAppId()); // should be 0x101/0x103
  printf("systemRunFlags: 0x%x\n", envGetSystemRunFlags()); // 0?

  puts("Initializing SysMenu stuff");

  //res = APT_LoadSysMenuArg(&menuarg);
  //printf("LoadSysMenuArg: %08X\n", res);

  if(res < 0)
  {
      memset(&menuarg, 0, sizeof(menuarg));
  }
  else
  {
      SysMenuArg dummy;
      memset(&dummy, 0, 0x40);
      //res = APT_StoreSysMenuArg(&dummy);
      //printf("StoreSysMenuArg: %08X\n", res);
  }

  puts("wat");

  // =====[VARS]=====

  u32 kDown;
  u32 kHeld;
  u32* fbBottom = gfxGetFramebuffer(GFX_BOTTOM, GFX_LEFT, NULL, NULL);
  u16 seed = 0;

  // =====[PREINIT]=====

  gspWaitForVBlank();
  gspWaitForVBlank();
  gspWaitForVBlank();


  //puts("Initializing nwm");
  //Result ret = nwmExtInit();
  //printf("nwmExt::Init %08X\n", ret);
  //puts("Initializing WiFi");
  //ret = NWMEXT_ControlWirelessEnabled(1);
  //printf("nwmExt::ControlWirelessEnabled %08X\n", ret);

  // =====[RUN]=====

  while (aptMainLoop())
  {
    hidScanInput();
    kDown = hidKeysDown();
    kHeld = hidKeysHeld();

    if (kHeld & KEY_SELECT)
    {
        *(u32*)0x00106800 = 0xDEADCAFE;
        break;
    }

    if(kDown & KEY_START)
    {
        Result res = 0;
        //u8 tst = 0;

        //puts("GetProgramIdOnAppJump");

        //u64 launchwat = 0;
        //FS_MediaType wattype = 0;

        //res = APT_GetProgramIdOnApplicationJump(NULL, NULL, &launchwat, &wattype);
        //printf("Result %08X %016LLX %i\n", res, launchwat, wattype);

        /*
        puts("CheckApp");
        res = APT_IsRegistered(0x400, &tst);
        printf("CheckApp result %08X %c\n", res, tst ? '+' : '-');
        if(tst)
        {
            puts("CheckApplet");
            res = APT_IsRegistered(0x200, &tst);
            printf("CheckApplet result %08X %c\n", res, tst ? '+' : '-');
            if(tst)
            {
                puts("CancelLibraryApplet");
                res = APT_CancelLibraryApplet(0);
                printf("CancelLibraryApplet result %08X\n", res);
            }
        }*/

        puts("PrepareToStartApp");
        //res = APT_PrepareToStartApplication(0x000400000F800100L, MEDIATYPE_SD, 1);
        res = APT_PrepareToStartApplication(0, MEDIATYPE_GAME_CARD, 0);
        if(res < 0)
        {
            printf("Fail %08X\n", res);
        }
        else
        {
            u8 hmac[0x20];
            u8 param[0x300];

            //memset(hmac, 0, sizeof(hmac));
            //memset(param, 0, sizeof(param));

            puts("Looping");
            do
            {
                res = APT_StartApplication(0, 0, 0, 0, 0);
                printf("Result %08X\n", res);
            }
            while(res == 0xC8A0CFF0 || res == 0xE0A0CC08 || res == 0xC8A0CC02);
            puts("Loop ended");
        }
    }

    if(kDown & KEY_B)
    {
        u32 __dummy = 0;
        NS_LaunchTitle(0, 0, &__dummy);
    }

    fbBottom[seed++] = 0xF00FCACE;

    //TODO implement

    gfxFlushBuffers();
    //gfxSwapBuffers();
    gspWaitForVBlank();
  }

  // =====[END]=====

  killswitch:

  gfxExit();

  return 0;
}
