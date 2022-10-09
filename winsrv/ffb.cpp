// FfbMon.cpp : Defines the entry point for the console application.
//

// Monitor Force Feedback (FFB) vJoy device
#include "Devioctl.h"
#include <malloc.h>
#include <string.h>
#include <stdlib.h>
#include "vjoywrapper.h"
#include "FfbMon.h"
#include "Math.h"
#include <stdio.h>

int ffb_direction = 0;
int ffb_strenght = 0;
int serial_result = 0;

JOYSTICK_POSITION_V2 iReport; // The structure that holds the full position data

int __cdecl main(int argc, char *argv[])
{
    int stat = 0;
    UINT DevID = DEV_ID;
    USHORT Z = 0;

    PVOID pPositionMessage;
    UINT IoCode = LOAD_POSITIONS;
    UINT IoSize = sizeof(JOYSTICK_POSITION);
    // HID_DEVICE_ATTRIBUTES attrib;
    BYTE id = 1;
    UINT iInterface = 1;

    // Set the target Joystick

    if (argc > 1)
        DevID = atol(argv[1]);

    // Get the driver attributes (Vendor ID, Product ID, Version Number)
    if (!vJoyEnabled())
    {
        printf("Function vJoyEnabled Failed\n");
        int dummy = getchar();
        stat = -2;
        return stat;
    }
    else
    {
        printf("Vendor: %s\nProduct :%s\nVersion Number:%s\n", static_cast<TCHAR *>(GetvJoyManufacturerString()), static_cast<TCHAR *>(GetvJoyProductString()), static_cast<TCHAR *>(GetvJoySerialNumberString()));
    };

    // Get FFB device
    if (!AcquireVJD(DevID))
    {
        printf("Failed to acquire vJoy device number %d.\n", DevID);
        int dummy = getchar();
        stat = -1;
        return stat;
    }
    else
        printf("Acquisita vJoy device numero %d - OK\n", DevID);

    VjdStat status = GetVJDStatus(DevID);

    switch (status)
    {
    case VJD_STAT_OWN:
        printf("vJoy device %d is  owned by this feeder\n", DevID);
        break;
    case VJD_STAT_FREE:
        printf("vJoy device %d is free\n", DevID);
        break;
    case VJD_STAT_BUSY:
        printf("vJoy device %d is already owned by another feeder\nCannot continue\n", DevID);
        return -3;
    case VJD_STAT_MISS:
        printf("vJoy device %d is not installed or disabled\nCannot continue\n", DevID);
        return -4;
    default:
        printf("vJoy device %d general error\nCannot continue\n", DevID);
        return -1;
    };

    // Acquire the target
    if ((status == VJD_STAT_OWN) || ((status == VJD_STAT_FREE) && (!AcquireVJD(DevID))))
    {
        printf("Did not acquire vJoy device number %d.\n", DevID);
        // return -1;
    }
    else
    {
        printf("Acquired: vJoy device number %d.\n", DevID);
    }

// Start FFB
#pragma warning(push)
#pragma warning(disable : 4996)
    BOOL Ffbstarted = FfbStart(DevID);
    if (!Ffbstarted)
    {
        printf("Failed to start FFB on vJoy device number %d.\n", DevID);
        int dummy = getchar();
        stat = -3;
        return stat;
    }
    else
        printf("Started FFB on vJoy device number %d - OK\n", DevID);
#pragma warning(pop)

    // Register Generic callback function
    FfbRegisterGenCB(FfbFunction1, &DevID);

    // Prepare for polling
    static FFBEType FfbEffect = (FFBEType)-1;
    char *FfbEffectName[] =
        {"NONE", "Constant Force", "Ramp", "Square", "Sine", "Triangle", "Sawtooth Up",
         "Sawtooth Down", "Spring", "Damper", "Inertia", "Friction", "Custom Force"};

    while (1)

    {

        id = (BYTE)DevID;
        iReport.bDevice = id;

        Sleep(2);

        Z += 350;

        iReport.wAxisZ = Z;

        pPositionMessage = (PVOID)(&iReport);

        if (!UpdateVJD(DevID, pPositionMessage))
        {
            printf("Feeding vJoy device number %d failed - try to enable device then press enter\n", DevID);
            int ch = getchar();
            AcquireVJD(DevID);
        }
    }

Exit:
    RelinquishVJD(DevID);
    return 0;
}

// Generic callback function
void CALLBACK FfbFunction(PVOID data)
{
    FFB_DATA *FfbData = (FFB_DATA *)data;
    int size = FfbData->size;
    printf("\nFFB Size %d\n", size);

    printf("Cmd:%08.8X ", FfbData->cmd);
    printf("ID:%02.2X ", FfbData->data[0]);
    printf("Size:%02.2d ", static_cast<int>(FfbData->size - 8));
    printf(" - ");
    for (UINT i = 0; i < FfbData->size - 8; i++)
        printf(" %02.2X", (UINT)FfbData->data[i]);
    printf("\n");
}

void CALLBACK FfbFunction1(PVOID data, PVOID userdata)
{
    // Packet Header
    printf("\n ============= FFB Packet size Size %d =============\n", static_cast<int>(((FFB_DATA *)data)->size));

/////// Packet Device ID, and Type Block Index (if exists)
#pragma region Packet Device ID, and Type Block Index
    int DeviceID, BlockIndex;
    FFBPType Type;
    TCHAR TypeStr[100];

    if (ERROR_SUCCESS == Ffb_h_DeviceID((FFB_DATA *)data, &DeviceID))
        printf("\n > Device ID: %d", DeviceID);
    if (ERROR_SUCCESS == Ffb_h_Type((FFB_DATA *)data, &Type))
    {
        if (!PacketType2Str(Type, TypeStr))
            printf("\n > Packet Type: %d", Type);
        else
            printf("\n > Packet Type: %s", TypeStr);
    }
    if (ERROR_SUCCESS == Ffb_h_EBI((FFB_DATA *)data, &BlockIndex))
        printf("\n > Effect Block Index: %d", BlockIndex);

#pragma endregion

/////// Effect Report
#pragma region Effect Report
#pragma warning(push)
#pragma warning(disable : 4996)
    FFB_EFF_CONST Effect;
    if (ERROR_SUCCESS == Ffb_h_Eff_Const((FFB_DATA *)data, &Effect))
    {
        if (!EffectType2Str(Effect.EffectType, TypeStr))
            printf("\n >> Effect Report: %02x", Effect.EffectType);
        else
            printf("\n >> Effect Report: %s", TypeStr);
#pragma warning(push)

        if (Effect.Polar)
        {
            printf("\n >> Direction: %d deg (%02x)", Polar2Deg(Effect.Direction), Effect.Direction);
        }
        else
        {
            printf("\n >> X Direction: %02x", Effect.DirX);
            printf("\n >> Y Direction: %02x", Effect.DirY);
        };

        if (Effect.Duration == 0xFFFF)
            printf("\n >> Duration: Infinit");
        else
            printf("\n >> Duration: %d MilliSec", static_cast<int>(Effect.Duration));

        if (Effect.TrigerRpt == 0xFFFF)
            printf("\n >> Trigger Repeat: Infinit");
        else
            printf("\n >> Trigger Repeat: %d", static_cast<int>(Effect.TrigerRpt));

        if (Effect.SamplePrd == 0xFFFF)
            printf("\n >> Sample Period: Infinit");
        else
            printf("\n >> Sample Period: %d", static_cast<int>(Effect.SamplePrd));

        printf("\n >> Gain: %d%%", Byte2Percent(Effect.Gain));
    };
#pragma endregion
#pragma region PID Device Control
    FFB_CTRL Control;
    TCHAR CtrlStr[100];
    if (ERROR_SUCCESS == Ffb_h_DevCtrl((FFB_DATA *)data, &Control) && DevCtrl2Str(Control, CtrlStr))
        printf("\n >> PID Device Control: %s", CtrlStr);

#pragma endregion
#pragma region Effect Operation
    FFB_EFF_OP Operation;
    TCHAR EffOpStr[100];
    if (ERROR_SUCCESS == Ffb_h_EffOp((FFB_DATA *)data, &Operation) && EffectOpStr(Operation.EffectOp, EffOpStr))
    {
        printf("\n >> Effect Operation: %s", EffOpStr);
        if (Operation.LoopCount == 0xFF)
            printf("\n >> Loop until stopped");
        else
            printf("\n >> Loop %d times", static_cast<int>(Operation.LoopCount));
    };
#pragma endregion
#pragma region Global Device Gain
    BYTE Gain;
    if (ERROR_SUCCESS == Ffb_h_DevGain((FFB_DATA *)data, &Gain))
        printf("\n >> Global Device Gain: %d", Byte2Percent(Gain));

#pragma endregion
#pragma region Condition
    FFB_EFF_COND Condition;
    if (ERROR_SUCCESS == Ffb_h_Eff_Cond((FFB_DATA *)data, &Condition))
    {
        if (Condition.isY)
            printf("\n >> Y Axis");
        else
            printf("\n >> X Axis");
        printf("\n >> Center Point Offset: %d", TwosCompWord2Int((WORD)Condition.CenterPointOffset) /**10000/127*/);
        printf("\n >> Positive Coefficient: %d", TwosCompWord2Int((WORD)Condition.PosCoeff) /**10000/127*/);
        printf("\n >> Negative Coefficient: %d", TwosCompWord2Int((WORD)Condition.NegCoeff) /**10000/127*/);
        printf("\n >> Positive Saturation: %d", Condition.PosSatur /**10000/255*/);
        printf("\n >> Negative Saturation: %d", Condition.NegSatur /**10000/255*/);
        printf("\n >> Dead Band: %d", Condition.DeadBand /**10000/255*/);
    }
#pragma endregion
#pragma region Envelope
    FFB_EFF_ENVLP Envelope;
    if (ERROR_SUCCESS == Ffb_h_Eff_Envlp((FFB_DATA *)data, &Envelope))
    {
        printf("\n >> Attack Level: %d", TwosCompWord2Int((WORD)Envelope.AttackLevel));
        printf("\n >> Fade Level: %d", TwosCompWord2Int((WORD)Envelope.FadeLevel));
        printf("\n >> Attack Time: %d", static_cast<int>(Envelope.AttackTime));
        printf("\n >> Fade Time: %d", static_cast<int>(Envelope.FadeTime));
    };

#pragma endregion
#pragma region Periodic
    FFB_EFF_PERIOD EffPrd;
    if (ERROR_SUCCESS == Ffb_h_Eff_Period((FFB_DATA *)data, &EffPrd))
    {
        printf("\n >> Magnitude: %d", EffPrd.Magnitude);
        printf("\n >> Offset: %d", TwosCompWord2Int(static_cast<WORD>(EffPrd.Offset)));
        printf("\n >> Phase: %d", EffPrd.Phase);
        printf("\n >> Period: %d", static_cast<int>(EffPrd.Period));
    };
#pragma endregion

#pragma region Effect Type
    FFBEType EffectType;
    if (ERROR_SUCCESS == Ffb_h_EffNew((FFB_DATA *)data, &EffectType))
    {
        if (EffectType2Str(EffectType, TypeStr))
            printf("\n >> Effect Type: %s", TypeStr);
        else
            printf("\n >> Effect Type: Unknown");
    }

#pragma endregion

#pragma region Ramp Effect
    FFB_EFF_RAMP RampEffect;
    if (ERROR_SUCCESS == Ffb_h_Eff_Ramp((FFB_DATA *)data, &RampEffect))
    {
        printf("\n >> Ramp Start: %d", TwosCompWord2Int((WORD)RampEffect.Start) /** 10000 / 127*/);
        printf("\n >> Ramp End: %d", TwosCompWord2Int((WORD)RampEffect.End) /** 10000 / 127*/);
    };

#pragma endregion

#pragma region Constant Effect
    FFB_EFF_CONSTANT ConstantEffect;
    if (ERROR_SUCCESS == Ffb_h_Eff_Constant((FFB_DATA *)data, &ConstantEffect))
    {
        printf("\n >> Constant Magnitude: %d", TwosCompWord2Int((WORD)ConstantEffect.Magnitude));
    };

#pragma endregion

    printf("\n");
    FfbFunction(data);
    printf("\n ====================================================\n");
}

// Convert Packet type to String
BOOL PacketType2Str(FFBPType Type, char * OutStr)
{
    BOOL stat = TRUE;
    char * Str = "";

    switch (Type)
    {
    case PT_EFFREP:
        Str = "Effect Report";
        break;
    case PT_ENVREP:
        Str = "Envelope Report";
        break;
    case PT_CONDREP:
        Str = "Condition Report";
        break;
    case PT_PRIDREP:
        Str = "Periodic Report";
        break;
    case PT_CONSTREP:
        Str = "Constant Force Report";
        break;
    case PT_RAMPREP:
        Str = "Ramp Force Report";
        break;
    case PT_CSTMREP:
        Str = "Custom Force Data Report";
        break;
    case PT_SMPLREP:
        Str = "Download Force Sample";
        break;
    case PT_EFOPREP:
        Str = "Effect Operation Report";
        break;
    case PT_BLKFRREP:
        Str = "PID Block Free Report";
        break;
    case PT_CTRLREP:
        Str = "PID Device Contro";
        break;
    case PT_GAINREP:
        Str = "Device Gain Report";
        break;
    case PT_SETCREP:
        Str = "Set Custom Force Report";
        break;
    case PT_NEWEFREP:
        Str = "Create New Effect Report";
        break;
    case PT_BLKLDREP:
        Str = "Block Load Report";
        break;
    case PT_POOLREP:
        Str = "PID Pool Report";
        break;
    default:
        stat = FALSE;
        break;
    }

    if (stat)
        strcpy_s(OutStr, 100, Str);

    return stat;
}

// Convert Effect type to String
BOOL EffectType2Str(FFBEType Type, char * OutStr)
{
    BOOL stat = TRUE;
    char * Str = "";

    switch (Type)
    {
    case ET_NONE:
        stat = FALSE;
        break;
    case ET_CONST:
        Str = "Constant Force";
        break;
    case ET_RAMP:
        Str = "Ramp";
        break;
    case ET_SQR:
        Str = "Square";
        break;
    case ET_SINE:
        Str = "Sine";
        break;
    case ET_TRNGL:
        Str = "Triangle";
        break;
    case ET_STUP:
        Str = "Sawtooth Up";
        break;
    case ET_STDN:
        Str = "Sawtooth Down";
        break;
    case ET_SPRNG:
        Str = "Spring";
        break;
    case ET_DMPR:
        Str = "Damper";
        break;
    case ET_INRT:
        Str = "Inertia";
        break;
    case ET_FRCTN:
        Str = "Friction";
        break;
    case ET_CSTM:
        Str = "Custom Force";
        break;
    default:
        stat = FALSE;
        break;
    };

    if (stat)
        strcpy_s(OutStr, 100, Str);

    return stat;
}

// Convert PID Device Control to String
BOOL DevCtrl2Str(FFB_CTRL Ctrl, char * OutStr)
{
    BOOL stat = TRUE;
    char * Str = "";

    switch (Ctrl)
    {
    case CTRL_ENACT:
        Str = "Enable Actuators";
        break;
    case CTRL_DISACT:
        Str = "Disable Actuators";
        break;
    case CTRL_STOPALL:
        Str = "Stop All Effects";
        break;
    case CTRL_DEVRST:
        Str = "Device Reset";
        break;
    case CTRL_DEVPAUSE:
        Str = "Device Pause";
        break;
    case CTRL_DEVCONT:
        Str = "Device Continue";
        break;
    default:
        stat = FALSE;
        break;
    }
    if (stat)
        strcpy_s(OutStr, 100, Str);

    return stat;
}

// Convert Effect operation to string
BOOL EffectOpStr(FFBOP Op, char * OutStr)
{
    BOOL stat = TRUE;
    char * Str = "";

    switch (Op)
    {
    case EFF_START:
        Str = "Effect Start";
        break;
    case EFF_SOLO:
        Str = "Effect Solo Start";
        break;
    case EFF_STOP:
        Str = "Effect Stop";
        break;
    default:
        stat = FALSE;
        break;
    }

    if (stat)
        strcpy_s(OutStr, 100, Str);

    return stat;
}

// Polar values (0x00-0xFF) to Degrees (0-360)
int Polar2Deg(BYTE Polar)
{
    return ((UINT)Polar * 360) / 255;
}

// Convert range 0x00-0xFF to 0%-100%
int Byte2Percent(BYTE InByte)
{
    return ((UINT)InByte * 100) / 255;
}

// Convert One-Byte 2's complement input to integer
int TwosCompByte2Int(BYTE in)
{
    int tmp;
    BYTE inv = ~in;
    BOOL isNeg = in >> 7;
    if (isNeg)
    {
        tmp = (int)(inv);
        tmp = -1 * tmp;
        return tmp;
    }
    else
        return (int)in;
}

// Convert One-Byte 2's complement input to integer
int TwosCompWord2Int(WORD in)
{
    int tmp;
    WORD inv = ~in;
    BOOL isNeg = in >> 15;
    if (isNeg)
    {
        tmp = (int)(inv);
        tmp = -1 * tmp;
        return tmp - 1;
    }
    else
        return (int)in;
}