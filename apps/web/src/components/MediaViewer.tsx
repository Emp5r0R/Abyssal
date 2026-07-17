import { Eye, FileArchive, X } from "lucide-react";
import type { DecryptedMedia } from "../domain/types";
import { IconButton } from "./Ui";

export function MediaViewer({ media, onClose }: { media: DecryptedMedia; onClose: () => void }) {
  return (
    <div className="media-viewer" role="dialog" aria-modal="true" aria-label={media.name} onContextMenu={(event) => event.preventDefault()}>
      <header>
        <div>
          <strong>{media.name}</strong>
          {media.oneTime ? <span><Eye size={14} /> ONE-TIME</span> : null}
        </div>
        <IconButton label="Close viewer" onClick={onClose}><X size={21} /></IconButton>
      </header>
      <div className="media-stage">
        {media.mediaType === "IMAGE" ? (
          <img src={media.objectUrl} alt={media.name} draggable={false} />
        ) : media.mediaType === "VIDEO" ? (
          <video
            src={media.objectUrl}
            controls
            autoPlay
            playsInline
            disablePictureInPicture
            controlsList="nodownload noremoteplayback"
          />
        ) : (
          <div className="file-preview-mark"><FileArchive size={48} /><span>{media.name}</span></div>
        )}
      </div>
    </div>
  );
}

