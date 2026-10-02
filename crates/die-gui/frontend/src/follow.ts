/**
 * Follow-in-Hex navigation bus.
 *
 * App registers a handler that jumps to the hex viewer at a file offset;
 * any deeply nested format table can call `followInHex(offset)` without
 * threading callbacks through props (mirrors upstream cross-view
 * "Follow in Hex" behavior).
 */

type FollowHandler = (offset: number) => void;

let hexHandler: FollowHandler | null = null;

/** Register the global follow-in-hex handler (called once by App). */
export function setFollowInHexHandler(h: FollowHandler | null): void {
  hexHandler = h;
}

/** Jump to the hex viewer at the given file offset, if a handler is set. */
export function followInHex(offset: number): void {
  hexHandler?.(offset);
}
