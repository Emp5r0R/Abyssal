import { Eye, FileArchive, X } from "lucide-react";
import { useId, useRef } from "react";
import type { DecryptedMedia } from "../domain/types";
import { IconButton } from "./Ui";
import { PrivacyBlur } from "./PrivacyBlur";
import { privacyBlurProps, usePrivacyBlur } from "./privacyBlurContext";
import { useDialogA11y } from "./useDialogA11y";

export function MediaViewer({ media, onClose }: { media: DecryptedMedia; onClose: () => void }) {
  const titleId = `${useId()}-title`;
  const descriptionId = `${titleId}-description`;
  const closeRef = useRef<HTMLButtonElement>(null);
  const blur = usePrivacyBlur();
  const viewerRef = useDialogA11y<HTMLDivElement>({ onClose, initialFocusRef: closeRef });

  return (
    <div
      ref={viewerRef}
      className="media-viewer"
      role="dialog"
      aria-modal="true"
      aria-labelledby={titleId}
      aria-describedby={descriptionId}
      tabIndex={-1}
      onContextMenu={(event) => event.preventDefault()}
    >
      <header>
        <div>
          <PrivacyBlur><strong id={titleId}>{media.name}</strong></PrivacyBlur>
          {media.oneTime ? <span className="badge"><Eye size={14} aria-hidden="true" />View once</span> : null}
        </div>
        <IconButton ref={closeRef} label="Close viewer" onClick={onClose}><X size={21} /></IconButton>
      </header>
      <p id={descriptionId} className="sr-only">Decrypted attachment preview. Content remains in the current browser process.</p>
      <div {...privacyBlurProps(blur, "media-stage")}>
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
