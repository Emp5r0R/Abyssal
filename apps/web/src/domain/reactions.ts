const REACTION_FILENAMES = [
  "alabama.gif",
  "alert.gif",
  "angel.gif",
  "angry.gif",
  "appreciate.gif",
  "azn.gif",
  "bang.gif",
  "blank.gif",
  "buenpost.gif",
  "catgirl.gif",
  "catyelling.gif",
  "chad.gif",
  "cheesy.gif",
  "chromeinternet.gif",
  "clowned.gif",
  "computer360.gif",
  "cool.gif",
  "cry.gif",
  "dancing.gif",
  "dark.gif",
  "embarrassed.gif",
  "emo.gif",
  "evil.gif",
  "extremelaugh.gif",
  "eyes.gif",
  "facepalm.gif",
  "fire.gif",
  "focus.gif",
  "glitchgumball.gif",
  "grin.gif",
  "gura_swag.png",
  "hamxorpepe.gif",
  "headbang.gif",
  "headtothefuckingwall.gif",
  "huh.gif",
  "joe_swag.png",
  "kiss.gif",
  "laugh.gif",
  "laughingatyou.gif",
  "lipsrsealed.gif",
  "minecraftpepe.png",
  "muscle.gif",
  "nono.gif",
  "pacman.gif",
  "panties.gif",
  "pepe_5head.png",
  "pepecry.gif",
  "pepedance.gif",
  "pepedj.gif",
  "pepedrive.gif",
  "pepehecker.gif",
  "peppe.gif",
  "phone.gif",
  "point.gif",
  "punch.gif",
  "redface.gif",
  "rolleyes.gif",
  "rotator.gif",
  "sad.gif",
  "sad2.gif",
  "salute.gif",
  "sassy.gif",
  "shocked.gif",
  "shoot.gif",
  "shrug.gif",
  "shush.gif",
  "shushing.gif",
  "sigh.gif",
  "skull360.gif",
  "smart.gif",
  "smiley.gif",
  "smirk.gif",
  "spinskull.gif",
  "tears.gif",
  "thisisfire.gif",
  "tick.gif",
  "tongue.gif",
  "tweakout.gif",
  "undecided.gif",
  "virus.gif",
  "virus1.gif",
  "waaa.gif",
  "weary.gif",
  "wink.gif",
  "world.gif",
  "wrong.gif",
  "yap.gif",
  "yay.gif",
] as const;

export interface ReactionAsset {
  filename: string;
  label: string;
  mimeType: "image/gif" | "image/png";
  path: string;
  shortcode: string;
}

export const REACTIONS: readonly ReactionAsset[] = Object.freeze(
  REACTION_FILENAMES.map((filename) => {
    const basename = filename.replace(/\.(gif|png)$/i, "").toLowerCase();
    return Object.freeze({
      filename,
      label: basename.replaceAll("_", " "),
      mimeType: filename.endsWith(".png") ? "image/png" as const : "image/gif" as const,
      path: `/abyssal-emojis/${filename}`,
      shortcode: `:${basename}:`,
    });
  }),
);

const REACTIONS_BY_SHORTCODE = new Map(REACTIONS.map((reaction) => [reaction.shortcode, reaction]));

export function reactionByShortcode(value: string | undefined): ReactionAsset | undefined {
  return value ? REACTIONS_BY_SHORTCODE.get(value.trim().toLowerCase()) : undefined;
}

export function exactReactionShortcut(value: string): ReactionAsset | undefined {
  return reactionByShortcode(value.trim());
}

export function searchReactions(query: string, limit = Number.POSITIVE_INFINITY): ReactionAsset[] {
  const clean = query.trim().toLowerCase().replace(/^:/, "").replace(/:$/, "");
  const matches = clean
    ? REACTIONS.filter((reaction) => reaction.filename.includes(clean) || reaction.shortcode.includes(clean))
    : REACTIONS;
  return matches.slice(0, limit);
}
