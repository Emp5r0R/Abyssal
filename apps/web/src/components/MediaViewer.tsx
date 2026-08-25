import { Eye, FileArchive, X } from "lucide-react";
import type { DecryptedMedia } from "../domain/types";
import { IconButton } from "./Ui";
import { PRIVACY_BLUR_CLASS, PrivacyBlur } from "./PrivacyBlur";

export function MediaViewer({ media, onClose }: { media: DecryptedMedia; onClose: () => void }) {
  return (
    <div className="media-viewer" role="dialog" aria-modal="true" aria-label="Decrypted attachment" onContextMenu={(event) => event.preventDefault()}>
      <header>
        <div>
          <PrivacyBlur><strong>{media.name}</strong></PrivacyBlur>
          {media.oneTime ? <span><Eye size={14} /> ONE-TIME</span> : null}
        </div>
        <IconButton label="Close viewer" onClick={onClose}><X size={21} /></IconButton>
      </header>
      <div className={`media-stage ${PRIVACY_BLUR_CLASS}`} tabIndex={0} data-privacy-blur="true">
        {media.mediaType === "IMAGE" ? (
          <img src={media.objectUrl} alt="Decrypted attachment" draggable={false} />
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
