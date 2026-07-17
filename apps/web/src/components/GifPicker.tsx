import { useState } from "react";
import { Search, X } from "lucide-react";
import { REACTIONS, searchReactions, type ReactionAsset } from "../domain/reactions";
import { IconButton } from "./Ui";

export function GifPicker({ onClose, onSelect }: { onClose: () => void; onSelect: (reaction: ReactionAsset) => void }) {
  const [query, setQuery] = useState("");
  const matches = query.trim() ? searchReactions(query) : REACTIONS;
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
        {matches.map((reaction) => (
          <button
            key={reaction.shortcode}
            type="button"
            onClick={() => onSelect(reaction)}
            title={reaction.shortcode}
            aria-label={`Send ${reaction.shortcode}`}
          >
            <span className="gif-thumb">
              <img src={reaction.path} alt="" loading="lazy" />
            </span>
            <code>{reaction.shortcode}</code>
          </button>
        ))}
      </div>
    </section>
  );
}
