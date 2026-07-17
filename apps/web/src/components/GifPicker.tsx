import { useState } from "react";
import { Search, X } from "lucide-react";
import { IconButton } from "./Ui";

const GIFS = [
  "appreciate.gif", "angry.gif", "angel.gif", "alert.gif", "bang.gif", "buenpost.gif",
  "catyelling.gif", "chad.gif", "cheesy.gif", "clowned.gif", "cool.gif", "cry.gif",
  "dancing.gif", "embarrassed.gif", "eyes.gif", "facepalm.gif", "fire.gif", "focus.gif",
  "grin.gif", "headbang.gif", "huh.gif", "kiss.gif", "laugh.gif", "pepecry.gif",
  "pepedance.gif", "pepedj.gif", "point.gif", "salute.gif", "shocked.gif", "shrug.gif",
  "smiley.gif", "smart.gif", "smirk.gif", "tears.gif", "thisisfire.gif", "tick.gif",
  "tongue.gif", "waaa.gif", "weary.gif", "wink.gif", "world.gif", "yay.gif",
];

export function GifPicker({ onClose, onSelect }: { onClose: () => void; onSelect: (path: string) => void }) {
  const [query, setQuery] = useState("");
  const matches = GIFS.filter((name) => name.includes(query.trim().toLowerCase()));
  return (
    <section className="gif-picker" aria-label="GIF reactions">
      <header>
        <label>
          <Search size={16} />
          <input aria-label="Search GIFs" placeholder="Search" value={query} onChange={(event) => setQuery(event.target.value)} />
        </label>
        <IconButton label="Close GIF picker" onClick={onClose}><X size={18} /></IconButton>
      </header>
      <div className="gif-grid">
        {matches.map((name) => (
          <button key={name} type="button" onClick={() => onSelect(`/abyssal-emojis/${name}`)} title={name.replace(/\.gif$/, "")}>
            <img src={`/abyssal-emojis/${name}`} alt={name.replace(/\.gif$/, "")} loading="lazy" />
          </button>
        ))}
      </div>
    </section>
  );
}

