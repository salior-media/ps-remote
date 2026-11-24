#include <stdio.h>
#include <string.h>
#include "chiaki/controller.h"
#include "chiaki/feedback.h"

static void hex(const uint8_t *b, size_t n) { for(size_t i = 0; i < n; i++) printf("%02x", b[i]); }

static ChiakiFeedbackState fs(float gx, float gy, float gz, float ax, float ay, float az,
		float ox, float oy, float oz, float ow, int16_t lx, int16_t ly, int16_t rx, int16_t ry)
{
	ChiakiFeedbackState s = { gx, gy, gz, ax, ay, az, ox, oy, oz, ow, lx, ly, rx, ry };
	return s;
}

static ChiakiFeedbackHistoryBuffer *g_history;
static void packet(void *user)
{
	(void)user;
	uint8_t buf[0x100]; size_t size = sizeof(buf);
	chiaki_feedback_history_buffer_format(g_history, buf, &size);
	printf(" "); hex(buf, size);
}

static void record(const char *name, const ChiakiControllerState *prev, const ChiakiControllerState *now)
{
	ChiakiFeedbackHistoryBuffer history;
	chiaki_feedback_history_buffer_init(&history, 0x10);
	g_history = &history;
	printf("record %s", name);
	chiaki_feedback_history_buffer_record_state(&history, NULL, prev, now, packet, NULL);
	printf("\n");
	chiaki_feedback_history_buffer_fini(&history);
}

int main(void)
{
	ChiakiFeedbackState states[] = {
		fs(0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0),
		fs(1.5f, -2.25f, 29.9f, 0.1f, -0.98f, 4.9f, 0, 0, 0, 1, 32767, -32768, 1234, -4321),
		fs(-29.9f, 0.001f, -7.5f, -4.9f, 0.5f, -1, 0.5f, -0.5f, 0.5f, -0.5f, -1, 1, -2, 2),
		fs(0, 0, 0, 0, 0, 0, -0.8f, 0.36f, 0.48f, 0, 0, 0, 0, 0),
		fs(0, 0, 0, 0, 0, 0, 0.1f, -0.9f, 0.3f, 0.3f, 100, 200, 300, 400),
		fs(0, 0, 0, 0, 0, 0, 0.2f, 0.1f, -0.95f, 0.2f, 0, 0, 0, 0),
		// values where (0xffff * d) / range and 0xffff * (d / range) truncate differently
		fs(-3.2121782f, 4.363926f, 13.378345f, 4.087205f, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0),
	};
	for(size_t i = 0; i < sizeof(states) / sizeof(states[0]); i++)
	{
		uint8_t buf[CHIAKI_FEEDBACK_STATE_BUF_SIZE_MAX];
		chiaki_feedback_state_format_v9(buf, &states[i]);
		printf("state_v9 %zu ", i); hex(buf, CHIAKI_FEEDBACK_STATE_BUF_SIZE_V9); printf("\n");
		chiaki_feedback_state_format_v12(buf, &states[i]);
		printf("state_v12 %zu ", i); hex(buf, CHIAKI_FEEDBACK_STATE_BUF_SIZE_V12); printf("\n");
	}

	uint8_t levels[] = { 0, 0x7f, 0xff };
	for(int bit = 0; bit < 19; bit++)
		for(size_t l = 0; l < 3; l++)
		{
			ChiakiFeedbackHistoryEvent e;
			memset(&e, 0, sizeof(e));
			ChiakiErrorCode err = chiaki_feedback_history_event_set_button(&e, 1ull << bit, levels[l]);
			printf("button %d %u ", bit, levels[l]);
			if(err != CHIAKI_ERR_SUCCESS) printf("invalid"); else hex(e.buf, e.len);
			printf("\n");
		}

	struct { bool down; uint8_t id; uint16_t x, y; } touches[] = {
		{ true, 0, 0, 0 }, { false, 5, 1919, 941 }, { true, 127, 960, 471 }, { true, 200, 0x123, 0x2ab },
	};
	for(size_t i = 0; i < sizeof(touches) / sizeof(touches[0]); i++)
	{
		ChiakiFeedbackHistoryEvent e;
		chiaki_feedback_history_event_set_touchpad(&e, touches[i].down, touches[i].id, touches[i].x, touches[i].y);
		printf("touch %d %u %u %u ", touches[i].down, touches[i].id, touches[i].x, touches[i].y); hex(e.buf, e.len); printf("\n");
	}

	ChiakiControllerState idle, a, b;
	chiaki_controller_state_set_idle(&idle);

	a = idle; a.buttons = CHIAKI_CONTROLLER_BUTTON_CROSS | CHIAKI_CONTROLLER_BUTTON_DPAD_DOWN | CHIAKI_CONTROLLER_BUTTON_PS;
	record("press_three", &idle, &a);
	record("release_three", &a, &idle);
	b = idle; b.buttons = CHIAKI_CONTROLLER_BUTTON_CROSS | CHIAKI_CONTROLLER_BUTTON_R3;
	record("swap", &a, &b);
	a = idle; a.l2_state = 0x40; a.r2_state = 0xff;
	b = a; b.l2_state = 0x80;
	record("triggers", &idle, &a);
	record("l2_moves", &a, &b);
	a = idle; chiaki_controller_state_start_touch(&a, 100, 200); chiaki_controller_state_start_touch(&a, 1800, 900);
	record("two_fingers_down", &idle, &a);
	b = a; chiaki_controller_state_set_touch_pos(&b, 1, 1700, 800);
	record("finger_moves", &a, &b);
	b = a; chiaki_controller_state_stop_touch(&b, 0); chiaki_controller_state_start_touch(&b, 5, 6);
	record("finger_replaced", &a, &b);
	a = idle;
	for(int i = 0; i < 12; i++) a.buttons |= 1u << i;
	record("twelve_at_once", &idle, &a);
	a = idle; chiaki_controller_state_start_touch(&a, 100, 200); a.buttons |= CHIAKI_CONTROLLER_BUTTON_TOUCHPAD;
	record("tap_down", &idle, &a);
	record("tap_up", &a, &idle);
	return 0;
}
