
#include <linux/input.h>

#ifdef __cplusplus
extern "C" {
#endif

extern char *events[EV_MAX + 1];
extern char *keys[KEY_MAX + 1];
extern char *absval[5];
extern char *relatives[REL_MAX + 1];
extern char *absolutes[ABS_MAX + 1];
extern char *misc[MSC_MAX + 1];
extern char *leds[LED_MAX + 1];
extern char *repeats[REP_MAX + 1];
extern char *sounds[SND_MAX + 1];
extern char **names[EV_MAX + 1];

#ifdef __cplusplus
}
#endif
