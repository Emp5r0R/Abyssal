/** True on Apple platforms, where shortcuts show ⌘ and ⌥ instead of Ctrl and Alt. */
export function isMacPlatform(nav: Pick<Navigator, "platform"> & { userAgentData?: { platform?: string } } = navigator): boolean {
  return /mac|iphone|ipad/iu.test(nav.userAgentData?.platform ?? nav.platform);
}
