import { SHORTCUTS } from "../domain/keyboardShortcuts";
import { isMacPlatform } from "../domain/platform";
import { Dialog } from "./Ui";

/** The list of shortcuts, shared by the help dialog and Settings. */
export function ShortcutList() {
  const mac = isMacPlatform();
  return (
    <dl className="shortcut-list">
      {SHORTCUTS.map((shortcut) => (
        <div key={shortcut.action} className="shortcut-row">
          <dt>{shortcut.description}</dt>
          <dd>
            {shortcut.keys(mac).map((key, index) => (
              <kbd key={`${key}-${index}`}>{key}</kbd>
            ))}
          </dd>
        </div>
      ))}
    </dl>
  );
}

export function ShortcutsDialog({ onClose }: { onClose: () => void }) {
  return (
    <Dialog
      title="Keyboard shortcuts"
      description="Shortcuts work anywhere in the workspace. / and ? are ignored while you type in a field."
      className="shortcuts-dialog"
      onClose={onClose}
      actions={<button className="primary-button" type="button" onClick={onClose}>Done</button>}
    >
      <ShortcutList />
    </Dialog>
  );
}
