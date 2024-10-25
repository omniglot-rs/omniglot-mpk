#include "ogdemo.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

// ---------- BASIC TESTS -----------------------------------------------------

extern size_t og_callback(size_t id, size_t arg0, size_t arg1, size_t arg2, size_t arg3);

void demo_nop(void) {}

size_t demo_return_size_t(void) {
	return 0xDEADBEEFCAFEBABE;
}

struct demo_two_size_t_struct demo_return_two_size_t_struct(void) {
	struct demo_two_size_t_struct s = {
		.x = 0xDEADBEEFCAFEBABE,
		.y = 0xFEEDFACECAFEBEEF,
	};
	return s;
}

struct demo_large_struct demo_return_large_struct(void) {
	struct demo_large_struct s = {
		.x = 0xDEADBEEFCAFEBABE,
		.y = 0xFEEDFACECAFEBEEF,
		.z = 0x0123456789ABCDEF,
	};
	return s;
}

void demo_3args(
	size_t a0, size_t a1, size_t a2
) {}

void demo_4args(
	size_t a0, size_t a1, size_t a2, size_t a3
) {}

void demo_5args(
	size_t a0, size_t a1, size_t a2, size_t a3, size_t a4
) {}

void demo_6args(
	size_t a0, size_t a1, size_t a2, size_t a3, size_t a4, size_t a5
) {}

void demo_7args(
	size_t a0, size_t a1, size_t a2, size_t a3, size_t a4, size_t a5, size_t a6
) {}

void demo_10args(
	size_t a0, size_t a1, size_t a2, size_t a3, size_t a4,
	size_t a5, size_t a6, size_t a7, size_t a8, size_t a9
) {}

void demo_25args(
	size_t a0, size_t a1, size_t a2, size_t a3, size_t a4,
	size_t a5, size_t a6, size_t a7, size_t a8, size_t a9,
	size_t a10, size_t a11, size_t a12, size_t a13, size_t a14,
	size_t a15, size_t a16, size_t a17, size_t a18, size_t a19,
	size_t a20, size_t a21, size_t a22, size_t a23, size_t a24
) {}

void demo_50args(
	size_t a0, size_t a1, size_t a2, size_t a3, size_t a4,
	size_t a5, size_t a6, size_t a7, size_t a8, size_t a9,
	size_t a10, size_t a11, size_t a12, size_t a13, size_t a14,
	size_t a15, size_t a16, size_t a17, size_t a18, size_t a19,
	size_t a20, size_t a21, size_t a22, size_t a23, size_t a24,
	size_t a25, size_t a26, size_t a27, size_t a28, size_t a29,
	size_t a30, size_t a31, size_t a32, size_t a33, size_t a34,
	size_t a35, size_t a36, size_t a37, size_t a38, size_t a39,
	size_t a40, size_t a41, size_t a42, size_t a43, size_t a44,
	size_t a45, size_t a46, size_t a47, size_t a48, size_t a49
) {}

void demo_100args(
	size_t a0, size_t a1, size_t a2, size_t a3, size_t a4,
	size_t a5, size_t a6, size_t a7, size_t a8, size_t a9,
	size_t a10, size_t a11, size_t a12, size_t a13, size_t a14,
	size_t a15, size_t a16, size_t a17, size_t a18, size_t a19,
	size_t a20, size_t a21, size_t a22, size_t a23, size_t a24,
	size_t a25, size_t a26, size_t a27, size_t a28, size_t a29,
	size_t a30, size_t a31, size_t a32, size_t a33, size_t a34,
	size_t a35, size_t a36, size_t a37, size_t a38, size_t a39,
	size_t a40, size_t a41, size_t a42, size_t a43, size_t a44,
	size_t a45, size_t a46, size_t a47, size_t a48, size_t a49,
	size_t a50, size_t a51, size_t a52, size_t a53, size_t a54,
	size_t a55, size_t a56, size_t a57, size_t a58, size_t a59,
	size_t a60, size_t a61, size_t a62, size_t a63, size_t a64,
	size_t a65, size_t a66, size_t a67, size_t a68, size_t a69,
	size_t a70, size_t a71, size_t a72, size_t a73, size_t a74,
	size_t a75, size_t a76, size_t a77, size_t a78, size_t a79,
	size_t a80, size_t a81, size_t a82, size_t a83, size_t a84,
	size_t a85, size_t a86, size_t a87, size_t a88, size_t a89,
	size_t a90, size_t a91, size_t a92, size_t a93, size_t a94,
	size_t a95, size_t a96, size_t a97, size_t a98, size_t a99
) {}

void demo_invoke_callback(void (*callback_fn)()) {
	callback_fn();
}

