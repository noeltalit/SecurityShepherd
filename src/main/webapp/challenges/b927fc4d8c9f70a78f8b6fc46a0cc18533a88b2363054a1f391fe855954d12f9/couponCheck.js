/*
 * Coupon codes are validated on the server only. This script used to ship every coupon code to
 * the browser, DES-encrypted with a key stored in the same file, which let anyone recover them.
 * It now only performs a cosmetic check that something was typed.
 */
function checkCoupon(code) {
	return typeof code === "string" && code.length > 0;
}
